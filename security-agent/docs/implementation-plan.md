# Device-resident Security Agent Implementation Plan

> For agentic workers: this plan documents execution explicitly requested by the user. It does not activate a separate Superpowers execution workflow. Work only in your assigned files; skip builds, lint, tests and formatters until the integration owner runs verification once all artifacts are complete. Do not commit.

**Goal:** Deliver a standalone Android app that configures and runs bounded cloud-directed assessments on a rooted phone, keeps secrets local, persists evidence and exports honest reports without a runtime host-computer dependency.

**Architecture:** Android framework UI and foreground service coordinate a synchronous worker using shared immutable protocol records. A cloud client proposes fixed-vocabulary actions; policy and the device gateway enforce target and network scope. Root commands are implementation details, never model actions.

**Tech Stack:** Kotlin 1.9.22, AGP 8.2.2, Gradle 8.2.1, JDK 17, Android compile/target 34 and minimum 23, Android framework UI, AccessibilityService, AndroidKeyStore AES/GCM, org.json, HttpsURLConnection, JUnit 4. The original repository-convention Kotlin 1.8.22/AGP 7.3.0/Gradle 7.6.3 pins were tried, but AGP 7.3 lint could not analyze the Kotlin metadata emitted by the new Kotlin bytecode. These updated pins apply only to security-agent; existing plugin projects remain unchanged. No Flutter, Node or desktop-tool dependency.

## Shared ownership and signatures

All production Kotlin code lives below `security-agent/app/src/main/kotlin/com/mekari/securityagent/`. Keep the single package `com.mekari.securityagent` for this small application; separate files by responsibility. RuntimeCore owns `AgentContract.kt` and creates it before other implementation work. These are the required shared signatures; additional private helpers are allowed but coordinate changes to these interfaces.

```kotlin
package com.mekari.securityagent

enum class SessionStatus { READY, RUNNING, PAUSED, COMPLETED, FAILED, STOPPED }
enum class ActionKind { TAP, TYPE_TEXT, ENTER_CREDENTIAL, SCROLL, BACK, WAIT, RUN_CHECK, REPORT_HYPOTHESIS, FINISH, REQUEST_HELP }
data class SessionConfig(
    val targetPackage: String,
    val endpoint: String,
    val model: String,
    val allowedHosts: List<String>,
    val maxSteps: Int = 40,
    val screenshotsToCloud: Boolean = false,
    val cloudConsent: Boolean = false
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
data class CheckResult(
    val checkId: String,
    val status: String,
    val summary: String,
    val findings: List<Finding> = emptyList(),
    val artifacts: List<String> = emptyList()
)
data class StepRecord(
    val index: Int,
    val at: Long,
    val action: AgentAction,
    val packageName: String,
    val outcome: String,
    val success: Boolean
)
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
    fun resetCancellation() {}
    fun cancel()
}
```

### RuntimeCore slice

**Owned files:** AgentContract.kt, CloudModelClient.kt, ActionPolicy.kt, SecretVault.kt, AgentRepository.kt, SessionController.kt, ReportRenderer.kt, Redactor.kt and their `app/src/test` behavioral tests.

- [ ] Create the records/interfaces above first and notify other workers.
- [ ] Implement strict JSON action decoding: reject unknown fields/kinds, excessive strings, arbitrary credential IDs, invalid check IDs and irrelevant fields. Supported check IDs: `manifest`, `storage`, `logs`, `network`, `screenshots`, `coverage`.
- [x] Implement HTTPS-only configurable OpenAI-compatible chat-completions requests to the full user-selected endpoint and model, with finite connection/read deadlines and cancellation disconnect. No automatic provider/model fallback, redirects, or unbounded retries. Validate model content and response size. Treat model output as untrusted. Do not send API key in JSON, credentials or screenshot bytes without consent.
- [ ] Implement local action policy: current fresh target observation, current node identity, permitted action/node combinations, bounded wait/scroll, no external app actions, known credential references only. Observe password nodes without values. TYPE_TEXT cannot serve as a path around credential handling.
- [ ] Implement Android Keystore encryption for secret IDs `cloud_api_key`, `username`, `password`. Use private atomic files, disable backup in manifest, never serialize secret values into SessionConfig.
- [ ] AgentRepository(context) public API: `saveConfig(config)`, `loadConfig(): SessionConfig?`, `setSecret(id,value)`, `getSecret(id): String?`, `createSession(config): SessionRecord`, `saveSession(record)`, `readSession(id): SessionRecord?`, `latestSession(): SessionRecord?`, `report(record): String`. ReportRenderer.render(record): String. Invalid/corrupt state must be visible, not silently reset to clean state.
- [x] SessionController run/pause/stop/resume persists state transitions, check results and action intent before mutation. Interrupted execution pauses and requires fresh observation; never replay pending mutations automatically. Collect baseline checks, launch target, then iterate fresh observations and validated actions to a finite maxSteps. Ensure root network scope release in finally and startup recovery; cleanup failure is persisted visibly. `ModelClient.resetCancellation()` clears a pre-registration cancellation before a valid new run. Device `prepare(config)` returns a readiness message on success and throws on refusal/failure; cleanup is attempted even if prepare fails.
- [x] Support `REPORT_HYPOTHESIS` as a separate, explicitly unverified model suggestion; reports keep it distinct from deterministic findings. Recover an interrupted owned network restriction before resume and retain report/evidence until user cleanup.
- [ ] Sanitize all cloud observations, action text/reasons, histories, reports, errors and persisted findings with the current credential set and bounded generic secret patterns. A root-visible private token is informational, not confirmed ordinary-attacker exploitation. Record model suggestions separately from deterministic findings.
- [ ] Add behavioral tests for scope escape/stale or wrong-package nodes, malformed/unknown actions, credential leakage, pause/stop/max-step transitions, export escaping and malformed persisted records. Do not test source text or plumbing.

### DeviceAutomation slice

**Owned files:** RootShell.kt, AgentAccessibilityService.kt, AndroidDeviceGateway.kt and optional device-specific tests.

- [ ] RootShell.run(script: String, timeoutMs: Long = 15000): RootResult, where RootResult(exitCode: Int, stdout: String, stderr: String), RootShell.quote(value): String. It is internal to executor/check implementations; no protocol action executes scripts. Bound output, drain stdout/stderr concurrently, enforce timeout and cancellation; never print commands or secrets. Maintain a cancel method if needed and coordinate it.
- [ ] AgentAccessibilityService exposes a live connected-instance status, fresh bounded target node traversal and node-by-path actions. ACTION_SET_TEXT enters Unicode/credentials without shell interpolation. Never persist or emit password-node text. Reject mismatched/expired observations and nodes whose actual package is not the target. Re-fetch before every action; do not retain live node objects across cloud requests. Implement scroll/back safely. Accessibility setup uses Android Settings; any root convenience must preserve other enabled services.
- [ ] AndroidDeviceGateway(context) implements DeviceGateway. prepare validates installed distinct UID target, accessibility, required root capability and network enforcement before launch. It uses ScopedFirewall(context, root).enforce(config): String and release(): String. Reject controller/system/shared-UID targets. Preserve baseline/no-code-hook labels.
- [ ] observe captures target UI, optional local screenshot via fixed root screencap command in a bounded private app-owned path, and never uploads anything itself. Password presence prevents screenshot upload. Screen-off/lock/external package is explicit intervention, not blind tapping.
- [ ] execute runs only the shared action vocabulary. Calls SecurityChecks(context, root).run(checkId, config, observation?) through collect. Root commands are fixed-purpose; model text never reaches shell commands. launch uses package launcher intent. endSession releases scope, closes resources and returns cleanup warnings.
- [ ] Do not require an external adb session at runtime. Report screenshot or accessibility failures explicitly.

### SecurityChecks slice

**Owned files:** SecurityChecks.kt, ScopedFirewall.kt and their behavioral tests. Coordinate RootShell usage with DeviceAutomation.

- [ ] ScopedFirewall(context, root).enforce(config): String and release(): String install only owned IPv4/IPv6 owner-UID chains. Resolve exact hostnames/IP literals before target launch; reject wildcard/URL/userinfo/empty host input. Reject non-distinct/shared/system UID. Allow only pinned destination addresses, handle both address families and roll back partial setup. Reject all other target destinations. Never flush unrelated chains. Persist enough owned-chain/UID state for startup recovery and show cleanup failures. Prevent concurrent sessions and stale restrictions. DNS refresh is explicit new-session work, not scope expansion.
- [ ] SecurityChecks(context, root).run(checkId: String, config: SessionConfig, observation: Observation? = null): CheckResult implements six IDs. manifest inspects installed PackageInfo/ApplicationInfo, debug/backup/cleartext configuration, declared permissions and exported components; avoid claiming exposure equals exploit. storage inspects bounded target private/shared paths through root, reports presence/path patterns without raw secret values, labels root requirements. logs reads bounded target-process logs and redacts secret-looking content, with explicit unavailable status on missing PID/tool/permission. network observes bounded socket metadata for target UID and records firewall scope; no claim of decrypted TLS inspection. screenshots records actual capture outcome and FLAG_SECURE coverage limitations, not an automatic vulnerability. coverage explicitly records unavailable deep code analysis, runtime TLS/crypto hooks, decrypted traffic, cross-account/business-logic checks and unexercised flows, rather than pretending these passed.
- [ ] Collector failure produces error/unavailable CheckResult, never a passing empty list. Bound command output and file scans. Never execute user/model strings as shell fragments. Do not open/modify unrelated app data or delete target data.

### AppShell slice

**Owned files:** all Gradle/wrapper/configuration files, AndroidManifest.xml, resources, MainActivity.kt, AgentService.kt, app/src/androidTest integration files. Root docs belong to integration owner.

- [x] Standalone app uses Gradle wrapper 8.2.1, Kotlin 1.9.22 and AGP 8.2.2; Android compile/target 34, min 23. Existing plugin projects remain unchanged.
- [ ] Manifest declares INTERNET, foreground-service/data-sync permissions, notification permission where relevant, query installed launchable packages, backup disabled, cleartext disabled, exported launcher only, non-exported foreground service, protected exported accessibility service with BIND_ACCESSIBILITY_SERVICE, accessibility XML configuration. Avoid broad storage permission and external control components. Foreground type dataSync for cloud requests, explicit user start and no boot receiver.
- [ ] Build a polished framework UI: white/light slate surfaces, deep navy text, restrained blue primary and orange risk indication; spacious readable forms with persistent labels and 48dp controls. Main sections: device readiness, target and exact hosts, cloud endpoint/model/API key, test credentials, max steps, disclosure and screenshot opt-in, start/progress/actions/report. Secret fields protected; do not place raw secrets in saved instance state or logs. Reports use severity text as well as color, selectable bounded output, document-picker Markdown export.
- [ ] Show installed launchable target selection and optionally Android APK document/install intent flow (request install source approval where needed); manual installed package entry remains available. Root/accessibility readiness has explicit setup actions and observable errors.
- [ ] AgentService manages one worker, foreground notification with pause/stop/open controls, repeated start protection, and SessionController. requestPause/requestStop must work during network waits. Load latest persisted session and display interrupted RUNNING as paused/recovery-needed. UI polling/receiver lifecycle must stop when Activity stops. Resume makes a fresh worker, fresh observation and never duplicates pending mutations.
- [ ] Add Android instrumentation smoke for actual app startup, secret-store round-trip and deterministic device collectors/agent-loop with a clearly labelled injected ModelClient. No cloud API key is bundled. Keep test-only activities/components out of release APK.

## Integration verification (integration owner only)

The integration owner runs build/lint/tests once the artifacts are complete. Documented commands are `./gradlew :app:assembleDebug :app:lintDebug :app:testDebugUnitTest :app:assembleDebugAndroidTest`; install both APKs and run `adb shell am instrument -w -r -e class com.mekari.securityagent.AssessmentSmokeTest com.mekari.securityagent.test/androidx.test.runner.AndroidJUnitRunner` on an unlocked, root-enabled device. Instrumentation uses a harmless test APK and deterministic test model adapter, not live cloud.

The app must not be represented as a completed full interaction-loop smoke or live staging assessment unless actually exercised. Its README records the exercised build/JVM checks and four on-device security checks; the full-loop status and any later evidence are maintained by the integration owner. A live cloud assessment requires user-supplied endpoint/model/key and authorized target/test credentials; do not put credentials in repository files or ask for secrets in chat.

Host UiAutomator2 may suppress accessibility services; instrumentation cycles only the already-enabled app service to rebind after process reset. Keep the device awake during development/usage where practical, while recognizing that app wake behavior cannot bypass manual lock, PIN, or reboot.

The live cloud assessment has no user-supplied endpoint/model/key or staging APK/accounts; it is not claimed or required for deterministic smoke. Never place credentials in repository files or ask the user to paste secrets into chat. Full device-loop evidence is maintained by the integration owner.
