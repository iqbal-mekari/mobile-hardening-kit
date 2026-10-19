package com.mekari.securityagent

import android.content.Context
import android.content.Intent
import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.util.UUID

/** Bridges session policy to the rooted device and the target-only accessibility service. */
internal class AndroidDeviceGateway(context: Context) : DeviceGateway {
    private val app = context.applicationContext
    private val root = RootShell()
    private val firewall = ScopedFirewall(app, root)
    private val checks = SecurityChecks(app, root)
    private var activeTarget: String? = null
    private var activeUid: Int? = null

    override fun prepare(config: SessionConfig): String = synchronized(SESSION_LOCK) {
        check(sessionLeaseOwner == null) { "Another assessment session still owns the device" }
        check(clearTransientModelScreenshot() == null) { "Cannot remove a transient screenshot from the previous session" }
        val validatedUid = validateTarget(config)
        if (!AgentAccessibilityService.isEnabled(app)) {
            throw IllegalStateException("Enable the assessment accessibility service in Android Settings")
        }
        if (!AgentAccessibilityService.isConnected()) {
            throw IllegalStateException("Assessment accessibility service is not connected")
        }
        val rootCheck = root.run("id", 30_000)
        if (rootCheck.exitCode != 0 || !rootCheck.stdout.contains("uid=0")) {
            throw IllegalStateException("Root access is unavailable; grant root permission to this app")
        }
        val message = firewall.enforce(config)
        activeUid = validatedUid
        activeTarget = config.targetPackage
        sessionLeaseOwner = this
        "$message Target process was force-stopped before network scope installation; cleanup must force-stop it again before scope removal. Baseline (no target-code hooks); root observations are privileged-device evidence only."

    }

    override fun launch(config: SessionConfig) {
        ensurePrepared(config)
        // Avoid using a stale activity/task left over from before scope was installed.
        checkedForceStop(config.targetPackage)
        val intent = app.packageManager.getLaunchIntentForPackage(config.targetPackage)
            ?: throw IllegalStateException("Target package has no launchable activity")
        if (intent.component?.packageName != config.targetPackage) throw IllegalStateException("Target launcher resolved outside the configured package")
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            app.startActivity(intent)
        } catch (e: Exception) {
            throw IllegalStateException("Unable to launch target app", e)
        }
    }

    override fun observe(config: SessionConfig): Observation {
        ensurePrepared(config)
        val service = AgentAccessibilityService.currentService()
            ?: return Observation("", emptyList(), error = "Accessibility service disconnected; user intervention required")
        val before = service.observeTarget(config.targetPackage)
        if (before.error != null || before.nodes.any { it.password } ||
            !config.screenshotsToCloud || !config.cloudConsent
        ) return before
        val screenshot = try {
            captureScreenshot(config.targetPackage, evidence = false)
        } catch (e: Exception) {
            return before.copy(error = "Local screenshot capture failed: ${e.message ?: "unknown error"}")
        }
        try {
            ensureTargetIdentity(config.targetPackage)
        } catch (e: Exception) {
            val cleanup = discardScreenshot(screenshot)
            return before.copy(error = "Target identity changed during screenshot capture: ${e.message ?: "unknown error"}${cleanup?.let { "; $it" }.orEmpty()}")
        }
        val after = service.observeTarget(config.targetPackage)
        if (after.error != null || after.nodes.any { it.password } || after.nodes != before.nodes) {
            val cleanup = discardScreenshot(screenshot)
            return after.copy(error = "Screenshot omitted because target screen, password state, or accessibility tree changed during capture${cleanup?.let { "; $it" }.orEmpty()}")
        }
        return after.copy(screenshotPath = screenshot.absolutePath)
    }

    override fun execute(action: AgentAction, observation: Observation, credential: String?): ActionResult {
        val target = activeTarget ?: return ActionResult(false, "No prepared target session")
        try {
            ensureTargetIdentity(target)
        } catch (e: Exception) {
            return ActionResult(false, e.message ?: "Target identity changed")
        }
        if (action.kind == ActionKind.RUN_CHECK || action.kind == ActionKind.REPORT_HYPOTHESIS ||
            action.kind == ActionKind.FINISH || action.kind == ActionKind.REQUEST_HELP
        ) {
            return ActionResult(false, "Controller-only action is not executable on the device")
        }
        if (action.kind == ActionKind.WAIT) {
            if (observation.error != null || observation.packageName != target) return ActionResult(false, "Observation is not a valid target-app snapshot")
            if (action.text.isNotEmpty()) return ActionResult(false, "Wait action does not accept text")
            val millis = action.reason.toLongOrNull() ?: return ActionResult(false, "Wait duration is invalid")
            if (millis !in 0..5_000) return ActionResult(false, "Wait duration exceeds the permitted bound")
            try { Thread.sleep(millis) } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                return ActionResult(false, "Wait was interrupted")
            }
            return ActionResult(true, "Wait completed")
        }
        val service = AgentAccessibilityService.currentService()
            ?: return ActionResult(false, "Accessibility service disconnected; user intervention required")
        return service.act(action, observation, target, credential)
    }

    override fun collect(checkId: String, config: SessionConfig): CheckResult {
        ensurePrepared(config)
        if (checkId != "screenshots") return checks.run(checkId, config, null)
        val service = AgentAccessibilityService.currentService()
            ?: return CheckResult(checkId, "unavailable", "Accessibility service disconnected")
        val before = service.observeTarget(config.targetPackage)
        if (before.error != null || before.nodes.any { it.password }) return checks.run(checkId, config, before)
        val screenshot = try {
            captureScreenshot(config.targetPackage, evidence = true)
        } catch (e: Exception) {
            return CheckResult(checkId, "unavailable", "Local screenshot capture failed: ${e.message ?: "unknown error"}")
        }
        try {
            ensureTargetIdentity(config.targetPackage)
        } catch (e: Exception) {
            val cleanup = discardScreenshot(screenshot)
            val detail = if (cleanup == null) "" else "; $cleanup"
            return CheckResult(checkId, "unavailable", "Target identity changed during screenshot capture: ${e.message ?: "unknown error"}$detail")
        }
        val after = service.observeTarget(config.targetPackage)
        if (after.error != null || after.nodes.any { it.password } || after.nodes != before.nodes) {
            val cleanup = discardScreenshot(screenshot)
            val detail = if (cleanup == null) "" else "; $cleanup"
            return CheckResult(checkId, "unavailable", "Screenshot discarded because target screen, password state, or accessibility tree changed during capture$detail")
        }
        return checks.run(checkId, config, after.copy(screenshotPath = screenshot.absolutePath))
    }

    override fun endSession(config: SessionConfig): List<String> = synchronized(SESSION_LOCK) {
        if (sessionLeaseOwner != null && sessionLeaseOwner !== this) {
            listOf("Another assessment still owns the device; no cleanup command was run")
        } else {
            try {
                val warnings = endSessionLocked(config).toMutableList()
                clearTransientModelScreenshot()?.let(warnings::add)
                warnings
            } finally {
                if (sessionLeaseOwner === this) {
                    sessionLeaseOwner = null
                    activeUid = null
                    activeTarget = null
                }
            }
        }
    }

    private fun endSessionLocked(config: SessionConfig): List<String> {
        val warnings = ArrayList<String>(2)
        if (activeTarget != null && activeTarget != config.targetPackage) {
            warnings += "Cleanup target did not match prepared target; scope remains installed"
            return warnings
        }
        if (activeTarget != null) {
            val identityMatches = try {
                ensureTargetIdentity(config.targetPackage)
                true
            } catch (e: Exception) {
                warnings += "Target identity changed; removing only validated owned rules: ${e.message ?: "unknown error"}"
                false
            }
            if (identityMatches) {
                try {
                    val result = root.forceStopPackage(config.targetPackage)
                    if (result.exitCode != 0) {
                        warnings += "Target force-stop failed; network scope retained: ${result.stderr.take(300)}"
                        return warnings
                    }
                } catch (e: Exception) {
                    warnings += "Target force-stop failed; network scope retained: ${e.message ?: "unknown error"}"
                    return warnings
                }
            }
        }
        try {
            val outcome = firewall.release()
            if (outcome.contains("; cleanup warning: ")) {
                warnings += outcome.substringAfter("; cleanup warning: ")
            }
        } catch (e: Exception) {
            warnings += "Network scope cleanup failed: ${e.message ?: "unknown error"}"
        }
        root.cancel()
        return warnings.filter { it.isNotBlank() }
    }

    fun recoverStaleScope(): String = synchronized(SESSION_LOCK) {
        check(sessionLeaseOwner == null) { "Cannot recover firewall scope while an assessment session is active" }
        firewall.recoverStale()

    }

    @Suppress("DEPRECATION")
    private fun validateTarget(config: SessionConfig): Int {
        require(android.os.Process.myUid() / UID_PER_USER == 0) { "Assessment is supported only in Android owner user 0; root force-stop is fixed to user 0" }
        require(config.targetPackage.isNotBlank() && config.targetPackage == config.targetPackage.trim()) { "Invalid target package" }
        val info = try {
            if (Build.VERSION.SDK_INT >= 33) app.packageManager.getApplicationInfo(config.targetPackage, android.content.pm.PackageManager.ApplicationInfoFlags.of(0))
            else app.packageManager.getApplicationInfo(config.targetPackage, 0)
        } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
            throw IllegalArgumentException("Target package is not installed")
        }
        require(config.targetPackage != app.packageName) { "Controller app cannot be assessed as a target" }
        require(info.uid / UID_PER_USER == 0) { "Target app is not installed in Android owner user 0" }
        require(info.uid >= 10_000) { "System or shared system UID targets are not permitted" }
        val packages = app.packageManager.getPackagesForUid(info.uid).orEmpty()
        require(packages.size == 1 && packages[0] == config.targetPackage) { "Shared-UID target packages are not permitted" }
        return info.uid
    }

    private fun ensurePrepared(config: SessionConfig) {
        if (activeTarget != config.targetPackage) throw IllegalStateException("Target session is not prepared")
        ensureTargetIdentity(config.targetPackage)
    }

    @Suppress("DEPRECATION")
    private fun ensureTargetIdentity(packageName: String) {
        val expectedUid = activeUid ?: throw IllegalStateException("Validated target UID is unavailable")
        val actualUid = try {
            if (Build.VERSION.SDK_INT >= 33) app.packageManager.getApplicationInfo(packageName, android.content.pm.PackageManager.ApplicationInfoFlags.of(0)).uid
            else app.packageManager.getApplicationInfo(packageName, 0).uid
        } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
            throw IllegalStateException("Validated target package is no longer installed")
        }
        if (actualUid != expectedUid) throw IllegalStateException("Target package UID changed after scope installation")
    }

    private fun checkedForceStop(packageName: String) {
        ensureTargetIdentity(packageName)
        val result = root.forceStopPackage(packageName)
        if (result.exitCode != 0) throw IllegalStateException("Unable to stop target before launch: ${result.stderr.take(300)}")
    }

    private fun captureScreenshot(target: String, evidence: Boolean): File {
        val service = AgentAccessibilityService.currentService()
            ?: throw IllegalStateException("Accessibility service disconnected")
        if (!service.isForegroundTarget(target)) throw IllegalStateException("Target is not foreground; screenshot capture refused")
        val uid = app.applicationInfo.uid
        val directory = File(app.filesDir, if (evidence) "assessment-screenshots" else "assessment-model-view").apply {
            if (!exists() && !mkdirs()) throw IllegalStateException("Cannot create private screenshot directory")
        }
        if (evidence) {
            val retained = directory.listFiles()?.count { it.isFile && it.extension == "png" } ?: 0
            if (retained >= MAX_RETAINED_SCREENSHOTS) throw IllegalStateException("Screenshot evidence retention limit reached; existing evidence was preserved")
        } else {
            directory.listFiles()?.filter { it.isFile && it.extension == "png" }?.forEach {
                if (!it.delete()) throw IllegalStateException("Cannot rotate transient model screenshot")
            }
        }
        val file = File(directory, "${UUID.randomUUID()}.png")
        val command = "screencap -p ${RootShell.quote(file.absolutePath)} && chown $uid:${app.applicationInfo.uid} ${RootShell.quote(file.absolutePath)} && chmod 600 ${RootShell.quote(file.absolutePath)}"
        val result = root.run(command, 10_000)
        if (result.exitCode != 0 || !file.isFile || file.length() !in 8..20_000_000) {
            val cleanup = discardScreenshot(file)
            throw IllegalStateException("Root screencap failed${cleanup?.let { "; $it" }.orEmpty()}")
        }
        if (!service.isForegroundTarget(target)) {
            val cleanup = discardScreenshot(file)
            throw IllegalStateException("Target left foreground during screenshot capture${cleanup?.let { "; $it" }.orEmpty()}")
        }
        val signature = ByteArray(8)
        try {
            FileInputStream(file).use { if (it.read(signature) != signature.size) throw IllegalStateException("Screenshot file is incomplete") }
        } catch (e: Exception) {
            val cleanup = discardScreenshot(file)
            throw IllegalStateException("${e.message ?: "Screenshot validation failed"}${cleanup?.let { "; $it" }.orEmpty()}", e)
        }
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
        if (!signature.contentEquals(png)) {
            val cleanup = discardScreenshot(file)
            throw IllegalStateException("Screenshot is not a PNG${cleanup?.let { "; $it" }.orEmpty()}")
        }
        return file
    }
    private fun clearTransientModelScreenshot(): String? {
        val directory = File(app.filesDir, "assessment-model-view")
        val files = directory.listFiles()?.filter { it.isFile && it.extension == "png" }.orEmpty()
        var failed = false
        for (file in files) if (!file.delete()) failed = true
        return if (failed) "Unable to remove transient local model screenshot" else null
    }

    private fun discardScreenshot(file: File): String? {
        return if (file.delete() || !file.exists()) null else "Screenshot cleanup failed; file remains in private storage"
    }

    companion object {
        private val SESSION_LOCK = Any()
        private var sessionLeaseOwner: AndroidDeviceGateway? = null
        private const val UID_PER_USER = 100_000
        private const val MAX_RETAINED_SCREENSHOTS = 5
    }
}
