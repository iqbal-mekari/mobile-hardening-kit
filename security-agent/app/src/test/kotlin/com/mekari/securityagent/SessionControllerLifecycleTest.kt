package com.mekari.securityagent

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SessionControllerLifecycleTest {
    private val config = SessionConfig("com.example.target", "https://api.example.test/v1/chat/completions", "selected-model", listOf("staging.example.test"), cloudConsent=true)

    @Test fun stopBeforeRunPreventsPreparationRequestsAndCleanup() {
        val store = MemoryStore(SessionRecord("ready", config))
        val device = RecordingDevice()
        val client = CountingClient(listOf(AgentAction(ActionKind.FINISH)))
        val controller = SessionController(store, device, client)
        controller.requestStop()
        controller.run("ready")
        assertEquals(SessionStatus.STOPPED, store.readSession("ready")!!.status)
        assertEquals(0, device.prepareCalls)
        assertEquals(0, client.calls)
        assertEquals(0, device.executeCalls)
        assertEquals(0, device.cleanupCalls)
    }

    @Test fun stopDuringObservationPreventsCloudRequestAndMutation() {
        val store = MemoryStore(SessionRecord("observing", config))
        val device = RecordingDevice()
        val entered = CountDownLatch(1)
        val resume = CountDownLatch(1)
        device.onObserve = { entered.countDown(); check(resume.await(5, TimeUnit.SECONDS)) }
        val client = CountingClient(listOf(AgentAction(ActionKind.TAP, "button")))
        val controller = SessionController(store, device, client)
        val worker = Thread { controller.run("observing") }
        worker.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        controller.requestStop()
        resume.countDown()
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertEquals(SessionStatus.STOPPED, store.readSession("observing")!!.status)
        assertEquals(0, client.calls)
        assertEquals(0, device.executeCalls)
        assertEquals(1, device.cleanupCalls)
    }

    @Test fun prepareFailureStillAttemptsScopeCleanup() {
        val store = MemoryStore(SessionRecord("prepare-failure", config))
        val device = RecordingDevice().apply { prepareFailure = true }
        val controller = SessionController(store, device, CountingClient(emptyList()))
        controller.run("prepare-failure")
        assertEquals(SessionStatus.FAILED, store.readSession("prepare-failure")!!.status)
        assertEquals(1, device.prepareCalls)
        assertEquals(1, device.cleanupCalls)
    }

    @Test fun pauseDuringObservationStopsBeforeRequest() {
        val store = MemoryStore(SessionRecord("pause-observe", config))
        val device = RecordingDevice()
        val entered = CountDownLatch(1)
        val resume = CountDownLatch(1)
        device.onObserve = { entered.countDown(); check(resume.await(5, TimeUnit.SECONDS)) }
        val client = CountingClient(listOf(AgentAction(ActionKind.TAP, "button")))
        val controller = SessionController(store, device, client)
        val worker = Thread { controller.run("pause-observe") }
        worker.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        controller.requestPause()
        resume.countDown()
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertEquals(SessionStatus.PAUSED, store.readSession("pause-observe")!!.status)
        assertEquals(0, client.calls)
        assertEquals(0, device.executeCalls)
    }

    @Test fun stopDuringCloudRequestCancelsClientAndPreventsQueuedAction() {
        val store = MemoryStore(SessionRecord("request-stop", config))
        val device = RecordingDevice()
        val client = BlockingClient()
        val controller = SessionController(store, device, client)
        val worker = Thread { controller.run("request-stop") }
        worker.start()
        assertTrue(client.entered.await(5, TimeUnit.SECONDS))
        controller.requestStop()
        worker.join(5_000)
        assertFalse(worker.isAlive)
        assertEquals(1, client.cancelCalls)
        assertEquals(SessionStatus.STOPPED, store.readSession("request-stop")!!.status)
        assertEquals(0, device.executeCalls)
    }
    @Test fun maxStepsCompletesAfterExactlyTheConfiguredActions() {
        val bounded = config.copy(maxSteps=1)
        val store = MemoryStore(SessionRecord("bounded", bounded))
        val device = RecordingDevice()
        val client = CountingClient(listOf(AgentAction(ActionKind.TAP, "button"), AgentAction(ActionKind.TAP, "button")))
        SessionController(store, device, client).run("bounded")
        val record = store.readSession("bounded")!!
        assertEquals(SessionStatus.COMPLETED, record.status)
        assertEquals(1, record.steps.size)
        assertEquals(1, device.executeCalls)
        assertTrue(record.checks.any { it.summary.startsWith("[post-run]") })
        assertEquals(1, record.visitedScreens.distinct().size)
        assertFalse(record.visitedScreens.isEmpty())
    }

    @Test fun hypothesesStaySeparateAndNormalCompletionCollectsPostRunEvidence() {
        val store = MemoryStore(SessionRecord("finished", config))
        val device = RecordingDevice()
        val client = CountingClient(listOf(
            AgentAction(ActionKind.REPORT_HYPOTHESIS, text="Possible exposure", reason="A staging UI label suggests it"),
            AgentAction(ActionKind.FINISH)
        ))
        SessionController(store, device, client).run("finished")
        val record = store.readSession("finished")!!
        assertEquals(SessionStatus.COMPLETED, record.status)
        assertEquals(0, device.executeCalls)
        assertTrue(record.checks.any { it.summary.startsWith("[baseline]") })
        assertTrue(record.checks.any { it.summary.startsWith("[post-run]") })
        assertTrue(record.findings.isEmpty())
        val report = ReportRenderer.render(record)
        assertTrue(report.contains("Model hypotheses — unverified"))
        assertTrue(report.contains("Possible exposure"))
        assertTrue(report.contains("not a deterministic finding"))
    }

    private class MemoryStore(initial: SessionRecord) : SessionStore {
        private val records = mutableMapOf(initial.id to initial)
        private val secrets = mutableMapOf("cloud_api_key" to "test-key")
        override fun getSecret(id: String) = secrets[id]
        override fun saveSession(record: SessionRecord) { records[record.id] = record }
        override fun readSession(id: String) = records[id]
    }

    private class CountingClient(private val actions: List<AgentAction>) : ModelClient {
        var calls = 0
        override fun next(config: SessionConfig, observation: Observation, history: List<StepRecord>, findings: List<Finding>, apiKey: String): AgentAction {
            calls++
            return actions.getOrElse(calls - 1) { AgentAction(ActionKind.FINISH) }
        }
        override fun cancel() { }
    }
    private class BlockingClient : ModelClient {
        val entered = CountDownLatch(1)
        private val release = CountDownLatch(1)
        var cancelCalls = 0
        override fun next(config: SessionConfig, observation: Observation, history: List<StepRecord>, findings: List<Finding>, apiKey: String): AgentAction {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            return AgentAction(ActionKind.TAP, "button")
        }
        override fun cancel() { cancelCalls++; release.countDown() }
    }

    private class RecordingDevice : DeviceGateway {
        var prepareCalls = 0
        var cleanupCalls = 0
        var executeCalls = 0
        var prepareFailure = false
        var onObserve: (() -> Unit)? = null
        override fun prepare(config: SessionConfig): String {
            prepareCalls++
            if (prepareFailure) throw IllegalStateException("controlled prepare failure")
            return "target prepared"
        }
        override fun launch(config: SessionConfig) { }
        override fun observe(config: SessionConfig): Observation {
            onObserve?.invoke()
            return Observation(config.targetPackage, listOf(UiNode("button", packageName=config.targetPackage, clickable=true)))
        }
        override fun execute(action: AgentAction, observation: Observation, credential: String?): ActionResult {
            executeCalls++
            return ActionResult(true, "executed")
        }
        override fun collect(checkId: String, config: SessionConfig): CheckResult = CheckResult(checkId, "complete", "deterministic $checkId result")
        override fun endSession(config: SessionConfig): List<String> { cleanupCalls++; return emptyList() }
    }
}
