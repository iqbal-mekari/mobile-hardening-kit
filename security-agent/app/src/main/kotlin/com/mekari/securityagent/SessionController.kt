package com.mekari.securityagent

import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

class SessionController(private val repository: SessionStore, private val device: DeviceGateway, private val client: ModelClient = CloudModelClient()) {
    private val stop = AtomicBoolean(false)
    private val pause = AtomicBoolean(false)
    private val lock = Any()

    fun requestPause() { pause.set(true); client.cancel() }
    fun requestStop() { stop.set(true); client.cancel() }

    fun run(sessionId: String, onUpdate: (SessionRecord) -> Unit = {}) {
        synchronized(lock) {
            if (!stop.get() && !pause.get()) client.resetCancellation()
            var record = repository.readSession(sessionId) ?: throw IllegalArgumentException("Assessment session not found")
            if (record.status !in setOf(SessionStatus.READY, SessionStatus.PAUSED, SessionStatus.RUNNING)) throw IllegalStateException("Session cannot run from ${record.status}")
            fun persist(status: SessionStatus, message: String = record.message) {
                val now = System.currentTimeMillis()
                record = Redactor.sanitizeRecord(record.copy(status=status, updatedAt=now, message=message), secrets())
                repository.saveSession(record)
                onUpdate(record)
            }
            fun finalSweep() {
                for (check in listOf("storage", "logs", "network", "screenshots")) {
                    if (checkInterruption() != null) return
                    val result = runCatching { device.collect(check, record.config) }
                        .getOrElse { CheckResult(check, "error", Redactor.redact(it.message ?: "Post-run collector failed", secrets())) }
                    val tagged = tagCheck(result, "post-run")
                    record = record.copy(checks=record.checks + tagged, findings=record.findings + tagged.findings)
                    persist(SessionStatus.RUNNING, "Post-run collector ${tagged.checkId}: ${tagged.status}")
                }
            }
            if (record.status == SessionStatus.RUNNING) {
                val last = record.steps.lastOrNull()
                if (last != null && last.outcome == "Intent recorded; action not yet applied") {
                    record = record.copy(steps = record.steps.dropLast(1) + last.copy(outcome = "Interrupted before completion; mutation was not replayed", success = false))
                }
                persist(SessionStatus.PAUSED, "Interrupted run recovered; a fresh target observation is required")
            }
            var cleanupRequired = false
            try {
                ActionPolicy.validateConfig(record.config)?.let { throw IllegalStateException(it) }
                val key = repository.getSecret("cloud_api_key") ?: throw IllegalStateException("Cloud API key is not configured")
                checkInterruption()?.let { persist(it.first, it.second); return }
                persist(SessionStatus.RUNNING, "Preparing target")
                checkInterruption()?.let { persist(it.first, it.second); return }
                cleanupRequired = true
                val readiness = device.prepare(record.config)
                persist(SessionStatus.RUNNING, Redactor.redact(readiness.ifBlank { "Target prepared" }, secrets()))
                checkInterruption()?.let { persist(it.first, it.second); return }
                device.launch(record.config)
                val requiredChecks = listOf("manifest", "storage", "logs", "network", "screenshots", "coverage")
                for (check in requiredChecks) {
                    if (record.checks.any { it.checkId == check && it.summary.startsWith("[baseline] ") }) continue
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    val result = runCatching { device.collect(check, record.config) }
                        .getOrElse { CheckResult(check, "error", Redactor.redact(it.message ?: "Collector failed", secrets())) }
                    val tagged = tagCheck(result, "baseline")
                    record = record.copy(checks=record.checks + tagged, findings=record.findings + tagged.findings)
                    persist(SessionStatus.RUNNING, "Collector ${tagged.checkId}: ${tagged.status}")
                }
                while (record.steps.size < record.config.maxSteps) {
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    val observation = device.observe(record.config)
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    val safeObservation = Redactor.sanitizeObservation(observation, secrets())
                    if (safeObservation.packageName != record.config.targetPackage || safeObservation.error != null) {
                        record = record.copy(steps=record.steps + StepRecord(record.steps.size + 1,System.currentTimeMillis(),AgentAction(ActionKind.REQUEST_HELP),safeObservation.packageName,safeObservation.error ?: "Target intervention required",false))
                        persist(SessionStatus.PAUSED, "Target UI unavailable or outside scope"); return
                    }
                    val fingerprint = screenFingerprint(safeObservation)
                    if (record.visitedScreens.size < MAX_VISITED_SCREENS && fingerprint !in record.visitedScreens) {
                        record = record.copy(visitedScreens = record.visitedScreens + fingerprint)
                        persist(SessionStatus.RUNNING, "Observed target screen $fingerprint")
                    }
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    val action = client.next(record.config, safeObservation, record.steps, record.findings, key)
                    // Cancellation is checked after response and before policy or any mutation.
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    val decision = ActionPolicy.validate(action, safeObservation, record.config)
                    if (action.kind == ActionKind.TYPE_TEXT && listOf("username", "password").mapNotNull { repository.getSecret(it) }.any { it.isNotEmpty() && action.text.contains(it) }) {
                        throw IllegalStateException("TYPE_TEXT cannot be used to enter configured credentials")
                    }
                    if (!decision.accepted) throw IllegalStateException("Rejected model action: ${decision.reason}")
                    val safeAction = Redactor.sanitizeAction(action, secrets())
                    record = record.copy(steps=record.steps + StepRecord(record.steps.size + 1,System.currentTimeMillis(),safeAction,record.config.targetPackage,"Intent recorded; action not yet applied",false))
                    persist(SessionStatus.RUNNING, "Action intent recorded")
                    checkInterruption()?.let { persist(it.first, it.second); return }
                    when (action.kind) {
                        ActionKind.FINISH -> {
                            record = record.copy(steps = record.steps.dropLast(1) + record.steps.last().copy(outcome = "Model requested assessment completion", success = true))
                            finalSweep()
                            checkInterruption()?.let { persist(it.first, it.second); return }
                            persist(SessionStatus.COMPLETED, "Model completed bounded assessment")
                            return
                        }
                        ActionKind.REQUEST_HELP -> {
                            record = record.copy(steps = record.steps.dropLast(1) + record.steps.last().copy(outcome = "User intervention requested", success = true))
                            persist(SessionStatus.PAUSED, Redactor.redact(action.reason.ifBlank { "User intervention requested" }, secrets()))
                            return
                        }
                        ActionKind.REPORT_HYPOTHESIS -> {
                            record = record.copy(steps = record.steps.dropLast(1) + record.steps.last().copy(outcome = "Unverified model hypothesis", success = true))
                        }
                        ActionKind.RUN_CHECK -> {
                            val result = device.collect(action.checkId,record.config)
                            val tagged = tagCheck(result, "interactive")
                            record = record.copy(checks=record.checks + tagged, findings=record.findings + tagged.findings, steps=record.steps.dropLast(1) + record.steps.last().copy(outcome=tagged.summary,success=tagged.status !in setOf("error", "unavailable")))
                        }
                        else -> {
                            val credential = if(action.kind == ActionKind.ENTER_CREDENTIAL) repository.getSecret(action.credentialId)
                                ?: throw IllegalStateException("Required credential is not configured") else null
                            val result = device.execute(action,observation,credential)
                            record = record.copy(steps=record.steps.dropLast(1) + record.steps.last().copy(outcome=Redactor.redact(result.message,secrets()),success=result.success))
                            if(!result.success) throw IllegalStateException(Redactor.redact(result.message,secrets()))
                        }
                    }
                    persist(SessionStatus.RUNNING,"Completed action ${action.kind}")
                }
                finalSweep()
                checkInterruption()?.let { persist(it.first, it.second); return }
                persist(SessionStatus.COMPLETED,"Maximum configured step count reached")
            } catch (e: Exception) {
                val status = if(stop.get()) SessionStatus.STOPPED else if(pause.get()) SessionStatus.PAUSED else SessionStatus.FAILED
                persist(status,Redactor.redact(e.message ?: "Assessment failed",secrets()))
            } finally {
                if (cleanupRequired) {
                    val cleanup = runCatching { device.endSession(record.config) }.getOrElse { listOf(Redactor.redact(it.message ?: "Session cleanup failed", secrets())) }
                    if (cleanup.isNotEmpty()) {
                        record = record.copy(message=Redactor.redact(record.message + "; cleanup warning: " + cleanup.joinToString("; "), secrets()), updatedAt=System.currentTimeMillis())
                        repository.saveSession(record); onUpdate(record)
                    }
                }
                stop.set(false)
                pause.set(false)
            }
        }
    }
    private fun checkInterruption(): Pair<SessionStatus,String>? = when { stop.get() -> SessionStatus.STOPPED to "Stopped by user; pending action was not replayed"; pause.get() -> SessionStatus.PAUSED to "Paused by user; fresh observation required"; else -> null }
    private fun tagCheck(result: CheckResult, phase: String): CheckResult = result.copy(
        summary = "[$phase] ${result.summary}",
        findings = result.findings.map { it.copy(phase = phase) }
    )
    private fun secrets() = listOf("cloud_api_key","username","password").mapNotNull { repository.getSecret(it) }
    private fun screenFingerprint(observation: Observation): String {
        val signature = observation.nodes.asSequence().take(200)
            .map { node -> node.resourceId.ifBlank { node.className } }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
            .take(40)
            .joinToString("|")
        val bytes = MessageDigest.getInstance("SHA-256").digest("${observation.packageName}|$signature".toByteArray(Charsets.UTF_8))
        return bytes.take(8).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
    private companion object { const val MAX_VISITED_SCREENS = 200 }
}
