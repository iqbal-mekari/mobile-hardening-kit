package com.mekari.securityagent

import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AssessmentSmokeTest {
    @Test fun realCollectorsLoopAndReportOnControlledTarget() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val testContext = instrumentation.context
        check(AgentAccessibilityService.isEnabled(context)) {
            "Enable Security Assessment inspection in Android Accessibility settings before running the on-device smoke."
        }
        val targetPackage = testContext.packageName
        val target = testContext.packageManager.getLaunchIntentForPackage(targetPackage)
            ?: error("Test-only smoke target is not installed or has no launcher activity")
        target.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        testContext.startActivity(target)
        reconnectEnabledAccessibilityService(context)
        val bindDeadline = android.os.SystemClock.elapsedRealtime() + 10_000L
        while (!AgentAccessibilityService.isConnected() && android.os.SystemClock.elapsedRealtime() < bindDeadline) {
            try {
                Thread.sleep(100)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IllegalStateException("Interrupted while waiting for Accessibility to reconnect.", e)
            }
        }
        check(AgentAccessibilityService.isConnected()) {
            "Accessibility remains enabled but did not reconnect to the test target within 10 seconds; reopen Accessibility settings and retry."
        }
        val repository = AgentRepository(context)
        // TEST-NET-1 is non-routable and accepted only as a pinned destination; the target makes no network requests.
        val config = SessionConfig(targetPackage, "https://localhost/v1/chat/completions", "test-only-deterministic", listOf("192.0.2.1"), 2, false, true)
        val device = AndroidDeviceGateway(context)
        val secretFiles = listOf("cloud_api_key", "username", "password").associateWith { id ->
            java.io.File(context.filesDir, "assessment/$id.enc").takeIf { it.exists() }?.readBytes()
        }
        // Retained evidence is capped; remove only this run's screenshots so repeated smokes do not exhaust the cap.
        val evidenceDirectory = java.io.File(context.filesDir, "assessment-screenshots")
        val preexistingEvidence = evidenceDirectory.listFiles()?.map { it.name }?.toSet().orEmpty()
        try {
            repository.setSecret("cloud_api_key", "TEST-ONLY-NOT-A-REAL-KEY")
            repository.setSecret("username", SmokeTargetActivity.TEST_USERNAME)
            repository.setSecret("password", SmokeTargetActivity.TEST_PASSWORD)
            device.prepare(config)
            try {
                device.launch(config)
                Thread.sleep(1200)
                val observation = device.observe(config)
                check(observation.error == null) { "Test target UI was not observable: ${observation.error}" }
                val continueNode = observation.nodes.firstOrNull { it.description == "Continue" && it.clickable }
                    ?: error("Controlled target Continue button was not exposed to Accessibility")
                assertAction(device.execute(AgentAction(ActionKind.TAP, nodeId = continueNode.id), observation, null), "Tap against controlled target")
                val afterTap = device.observe(config)
                check(afterTap.nodes.any { it.text == "Credential mismatch" }) { "Target did not reflect the tap action." }

                val usernameSnapshot = device.observe(config)
                val usernameNode = usernameSnapshot.nodes.firstOrNull { it.editable && !it.password }
                    ?: error("Controlled target username field was not exposed to Accessibility")
                assertAction(device.execute(AgentAction(ActionKind.TYPE_TEXT, nodeId = usernameNode.id, text = SmokeTargetActivity.TEST_USERNAME), usernameSnapshot, null), "Unicode username entry")
                val afterUsername = device.observe(config)
                check(afterUsername.nodes.any { it.editable && !it.password && it.text == SmokeTargetActivity.TEST_USERNAME }) {
                    "The controlled target did not receive the synthetic Unicode username."
                }

                val passwordSnapshot = device.observe(config)
                val passwordNode = passwordSnapshot.nodes.firstOrNull { it.editable && it.password }
                    ?: error("Controlled target password field was not exposed to Accessibility")
                check(passwordNode.text.isEmpty() && passwordNode.description.isEmpty()) { "Password-node contents were exposed in the observation." }
                assertAction(device.execute(AgentAction(ActionKind.ENTER_CREDENTIAL, nodeId = passwordNode.id, credentialId = "password"), passwordSnapshot, repository.getSecret("password")), "Credential entry")
                val afterPassword = device.observe(config)
                val hiddenPasswordNode = afterPassword.nodes.firstOrNull { it.editable && it.password }
                    ?: error("Controlled target password field disappeared")
                check(hiddenPasswordNode.text.isEmpty() && hiddenPasswordNode.description.isEmpty()) {
                    "Password-node contents were exposed after credential entry."
                }
                val submitNode = afterPassword.nodes.firstOrNull { it.description == "Continue" && it.clickable }
                    ?: error("Controlled target Continue button was not exposed after credential entry")
                assertAction(device.execute(AgentAction(ActionKind.TAP, nodeId = submitNode.id), afterPassword, null), "Credential submission tap")
                check(device.observe(config).nodes.any { it.text == "Credentials accepted" }) {
                    "The controlled target did not accept both synthetic credentials."
                }
                val clearUserObservation = device.observe(config)
                val clearUser = clearUserObservation.nodes.first { it.editable && !it.password }
                assertAction(device.execute(AgentAction(ActionKind.TYPE_TEXT, nodeId = clearUser.id, text = ""), clearUserObservation, null), "Synthetic username clearing")
                val clearPasswordObservation = device.observe(config)
                val clearPassword = clearPasswordObservation.nodes.first { it.editable && it.password }
                assertAction(device.execute(AgentAction(ActionKind.ENTER_CREDENTIAL, nodeId = clearPassword.id, credentialId = "password"), clearPasswordObservation, ""), "Synthetic password clearing")
                val summaryObservation = device.observe(config)
                val summaryButton = summaryObservation.nodes.firstOrNull { it.description == "Show summary" && it.clickable }
                    ?: error("Controlled target summary control was not exposed")
                assertAction(device.execute(AgentAction(ActionKind.TAP, nodeId = summaryButton.id), summaryObservation, null), "Credential-free summary transition")
                val summaryScreen = device.observe(config)
                check(summaryScreen.nodes.any { it.text == "Controlled assessment summary" } && summaryScreen.nodes.none { it.password }) {
                    "Controlled target did not transition to the credential-free summary screen."
                }
            } finally {
                device.endSession(config)
            }

            val session = repository.createSession(config)
            var controlledSteps = 0
            val controlledClient = object : ModelClient {
                override fun next(config: SessionConfig, observation: Observation, history: List<StepRecord>, findings: List<Finding>, apiKey: String): AgentAction {
                    controlledSteps++
                    if (controlledSteps == 1) {
                        val summaryNode = observation.nodes.firstOrNull { it.description == "Show summary" && it.clickable }
                            ?: error("Controlled model did not receive the fixture summary control.")
                        return AgentAction(ActionKind.TAP, nodeId = summaryNode.id)
                    }
                    check(observation.nodes.any { it.text == "Controlled assessment summary" } && observation.nodes.none { it.password }) {
                        "Controlled model did not observe the credential-free summary after its tap."
                    }
                    return AgentAction(ActionKind.FINISH)
                }
                override fun cancel() = Unit
            }
            SessionController(repository, AndroidDeviceGateway(context), controlledClient).run(session.id)
            val completed = repository.readSession(session.id) ?: error("Session persistence failed")
            assertEquals(completed.message, SessionStatus.COMPLETED, completed.status)
            val baseline = completed.checks.filter { it.summary.startsWith("[baseline] ") }
            val postRun = completed.checks.filter { it.summary.startsWith("[post-run] ") }
            assertTrue("Baseline collector coverage is missing", baseline.map { it.checkId }.containsAll(listOf("manifest", "storage", "logs", "network", "screenshots", "coverage")))
            assertTrue("Post-run collector sweep is missing", postRun.map { it.checkId }.containsAll(listOf("storage", "logs", "network", "screenshots")))
            val screenshotEvidence = completed.checks.filter { it.checkId == "screenshots" }.flatMap { it.artifacts }
            assertTrue("No retained screenshot evidence was recorded", screenshotEvidence.any { path ->
                val artifact = java.io.File(path)
                artifact.isFile && artifact.canonicalPath.startsWith(context.filesDir.canonicalPath + java.io.File.separator)
            })
            val markdown = repository.report(completed)
            assertTrue("API key leaked into the report", !markdown.contains("TEST-ONLY-NOT-A-REAL-KEY"))
            assertTrue("Synthetic username leaked into the report", !markdown.contains(SmokeTargetActivity.TEST_USERNAME))
            assertTrue("Synthetic password leaked into the report", !markdown.contains(SmokeTargetActivity.TEST_PASSWORD))
            val persisted = java.io.File(context.filesDir, "assessment/sessions/${session.id}.json").readText()
            assertTrue("Secret leaked into persisted session data", listOf("TEST-ONLY-NOT-A-REAL-KEY", SmokeTargetActivity.TEST_USERNAME, SmokeTargetActivity.TEST_PASSWORD).none(persisted::contains))
            val logEntries = repository.readLog(session.id)
            assertTrue("Session log captured no entries", logEntries.isNotEmpty())
            assertTrue("Session log missing lifecycle completion entry", logEntries.any { it.category == "lifecycle" && it.message.contains("COMPLETED") })
            val logExport = repository.exportLog(session.id)
            assertTrue("Secret leaked into exported session log", listOf("TEST-ONLY-NOT-A-REAL-KEY", SmokeTargetActivity.TEST_USERNAME, SmokeTargetActivity.TEST_PASSWORD).none(logExport::contains))
        } finally {
            secretFiles.forEach { (id, previous) ->
                val file = java.io.File(context.filesDir, "assessment/$id.enc")
                if (previous == null) file.delete() else file.writeBytes(previous)
            }
            evidenceDirectory.listFiles()?.filter { it.name !in preexistingEvidence }?.forEach { it.delete() }
        }
    }

    private fun assertAction(result: ActionResult, actionLabel: String) {
        check(result.success) { "$actionLabel failed: ${result.message}" }
    }

    private fun reconnectEnabledAccessibilityService(context: Context) {
        val component = android.content.ComponentName(context, AgentAccessibilityService::class.java).flattenToString()
        val root = RootShell()
        fun readEnabledServices(): List<String> {
            val result = root.run("settings get secure enabled_accessibility_services", 5_000)
            check(result.exitCode == 0) { "Could not read enabled Accessibility services: ${result.stderr}" }
            return result.stdout.trim().takeUnless { it.isEmpty() || it == "null" }?.split(':')?.filter { it.isNotBlank() }.orEmpty()
        }
        fun writeEnabledServices(services: List<String>) {
            val result = root.run(
                "settings put secure enabled_accessibility_services ${RootShell.quote(services.joinToString(":"))}",
                5_000
            )
            check(result.exitCode == 0) { "Could not update the already-enabled assessment service: ${result.stderr}" }
        }

        val initiallyEnabled = readEnabledServices()
        check(component in initiallyEnabled) {
            "Enable Security Assessment inspection in Android Accessibility settings before running the on-device smoke."
        }
        val unrelatedInitially = initiallyEnabled.filterNot { it == component }
        try {
            writeEnabledServices(unrelatedInitially)
            val disabledState = readEnabledServices()
            check(component !in disabledState && disabledState.containsAll(unrelatedInitially)) {
                "Accessibility service toggle changed another enabled service; refusing to continue."
            }
            writeEnabledServices(disabledState + component)
            val restoredState = readEnabledServices()
            check(component in restoredState && restoredState.containsAll(unrelatedInitially)) {
                "Assessment service was not restored with the other Accessibility services preserved."
            }
        } catch (failure: Exception) {
            try {
                val current = readEnabledServices()
                if (component !in current) writeEnabledServices(current + component)
            } catch (restoreFailure: Exception) {
                failure.addSuppressed(restoreFailure)
            }
            throw failure
        }
    }
}
