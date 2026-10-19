package com.mekari.securityagent

import java.util.UUID

enum class SessionStatus { READY, RUNNING, PAUSED, COMPLETED, FAILED, STOPPED }
enum class ActionKind { TAP, TYPE_TEXT, ENTER_CREDENTIAL, SCROLL, BACK, WAIT, RUN_CHECK, REPORT_HYPOTHESIS, FINISH, REQUEST_HELP }

/** Wire protocol for the cloud reasoning model. OPENAI covers any OpenAI-compatible chat-completions endpoint. */
enum class ModelProvider { OPENAI, ANTHROPIC }

data class SessionConfig(
    val targetPackage: String,
    val endpoint: String,
    val model: String,
    val allowedHosts: List<String>,
    val maxSteps: Int = 40,
    val screenshotsToCloud: Boolean = false,
    val cloudConsent: Boolean = false,
    // Appended last with defaults so existing positional construction sites remain valid.
    val provider: ModelProvider = ModelProvider.OPENAI,
    val liveAdvisories: Boolean = false,
    val advisoryEndpoint: String = ""
)

data class UiNode(
    val id: String,
    val text: String = "",
    val description: String = "",
    val resourceId: String = "",
    val className: String = "",
    val packageName: String = "",
    val editable: Boolean = false,
    val password: Boolean = false,
    val clickable: Boolean = false,
    val bounds: String = ""
)

data class Observation(
    val packageName: String,
    val nodes: List<UiNode>,
    val capturedAt: Long = System.currentTimeMillis(),
    val screenshotPath: String? = null,
    val error: String? = null
)

data class AgentAction(
    val kind: ActionKind,
    val nodeId: String = "",
    val text: String = "",
    val credentialId: String = "",
    val direction: String = "",
    val checkId: String = "",
    val reason: String = ""
)
data class ActionResult(val success: Boolean, val message: String)
data class Finding(
    val id: String,
    val title: String,
    val severity: String,
    val confidence: String,
    val evidence: String,
    val attackerPrerequisite: String,
    val remediation: String,
    val phase: String = "baseline"
)
data class CheckResult(val checkId: String, val status: String, val summary: String, val findings: List<Finding> = emptyList(), val artifacts: List<String> = emptyList())
/** One sanitized, timestamped line in a session's verbose process log. */
data class LogEvent(val at: Long, val level: String, val category: String, val message: String)
data class StepRecord(val index: Int, val at: Long, val action: AgentAction, val packageName: String, val outcome: String, val success: Boolean)
data class SessionRecord(
    val id: String,
    val config: SessionConfig,
    val status: SessionStatus = SessionStatus.READY,
    val startedAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val message: String = "Ready",
    val steps: List<StepRecord> = emptyList(),
    val checks: List<CheckResult> = emptyList(),
    val findings: List<Finding> = emptyList(),
    val visitedScreens: List<String> = emptyList()
)
interface DeviceGateway {
    fun prepare(config: SessionConfig): String
    fun launch(config: SessionConfig)
    fun observe(config: SessionConfig): Observation
    fun execute(action: AgentAction, observation: Observation, credential: String?): ActionResult
    fun collect(checkId: String, config: SessionConfig): CheckResult
    fun endSession(config: SessionConfig): List<String>
}
interface ModelClient {
    fun next(config: SessionConfig, observation: Observation, history: List<StepRecord>, findings: List<Finding>, apiKey: String): AgentAction
    fun cancel()
    fun resetCancellation() {}
    /** Fetch the provider's selectable model identifiers. Default empty so test doubles need not implement it. */
    fun listModels(config: SessionConfig, apiKey: String): List<String> = emptyList()
    /** Supply sanitized, untrusted live-advisory reference text for subsequent next() calls. No-op by default. */
    fun provideAdvisories(text: String) {}
    /** Attach a sink that receives sanitized model request/response log events. No-op by default. */
    fun attachLogger(sink: (LogEvent) -> Unit) {}
}
interface SessionStore {
    fun getSecret(id: String): String?
    fun saveSession(record: SessionRecord)
    fun readSession(id: String): SessionRecord?
    /** Append one sanitized line to the session's verbose log. No-op by default so in-memory test stores need not persist logs. */
    fun appendLog(sessionId: String, event: LogEvent) {}
}
internal fun newSessionId(): String = UUID.randomUUID().toString()
