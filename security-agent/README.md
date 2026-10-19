# Security Agent (Android)

A standalone Android application for authorized, bounded assessment of an installed staging APK on a rooted Android phone. It combines local Android collectors and accessibility-driven exploration with cloud model reasoning over explicitly disclosed observations. It does not require a host computer after provisioning. This project is separate from `mobile_hardening_kit`: it is not a plugin, does not add detectors to the library, and does not change its API or security boundary.

This is a staging assessment aid, not a certification, exhaustive scanner, or source of confirmed vulnerabilities. Use only targets and test accounts you are authorized to assess. Never use production credentials/accounts or submit secrets in chat or repository files.

## Requirements and build

- macOS/Linux host with JDK 17 and Android SDK/platform/build-tools 34 installed; `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) configured.
- Gradle wrapper 8.2.1, Android Gradle Plugin 8.2.2, Kotlin 1.9.22; compile/target SDK 34, minimum Android API 23. The standalone project has no Flutter/Node dependency. Existing plugin projects retain their own toolchain.
- An unlocked, rooted Android device running owner user 0 for assessments; root access and this app's accessibility service must be enabled. USB debugging/ADB is used for development installation only.

From this directory:

```sh
./gradlew :app:assembleDebug :app:lintDebug :app:testDebugUnitTest :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r -e class com.mekari.securityagent.AssessmentSmokeTest com.mekari.securityagent.test/androidx.test.runner.AndroidJUnitRunner
```

The instrumentation smoke requires the device to be unlocked and root-enabled. It uses the harmless test APK and a deterministic test-only model adapter; it does not call a live cloud service or assess a real staging app. The live cloud-driven assessment additionally requires user-supplied endpoint, selected model, API key, authorized staging target, and dedicated test credentials, entered locally in the app. Do not share secrets in chat.

Install/open the app, then use **Check root access** and **Open accessibility settings** to grant its own assessment accessibility service. Select or install the authorized staging APK, enter its installed package ID, and configure exact allowed staging hostnames. Android may require approving installation from this source when using the in-app APK picker. Root and accessibility are runtime prerequisites; failure to grant either prevents assessment.

## Configure an assessment

- **Provider and endpoint:** choose **OpenAI-compatible** or **Anthropic**. OpenAI-compatible sends an OpenAI Chat Completions request to the exact HTTPS URL you enter (the field placeholder defaults to the first-party `https://api.openai.com/v1/chat/completions`, but any compatible endpoint is accepted); auth uses a bearer token. Anthropic uses the Messages API at `https://api.anthropic.com/v1/messages` with `x-api-key` and a pinned `anthropic-version`. No provider URL is inferred beyond this and no model is selected automatically. No SDK is bundled; both providers are called over raw HTTPS.
- **Model:** enter a model name, or press **Fetch models** to list the provider's models (via its models endpoint, using your API key) and pick one. The selection is stored locally. No model is bundled or silently substituted.
- **API key:** enter locally. API key, staging username and password are encrypted with Android Keystore AES/GCM in app-private storage; they are not included in reports/session records. Secret inputs are blank after reload: leaving a secret field blank retains its already-saved value; entering a replacement updates it.
- **Target and scope:** choose an installed launchable target or install an APK. Enter exact allowed hostnames (no wildcard). The agent resolves them before launch and pins the resulting destination IP addresses in its target-UID firewall scope. It does not expand scope from redirects or later DNS changes. Shared CDN/IP destinations can make legitimate target traffic inaccessible; IPs shared with unrelated services and address changes limit what host-based policy can distinguish. Isolated-process traffic may not share the app UID and is not covered. The scope is not a general device VPN/firewall.
- **Disclosure:** explicitly enable sanitized text observation disclosure before text can be sent to the cloud. Screenshot upload is a separate, password-gated opt-in; screenshots are not sent when password nodes are present. Do not include sensitive customer or personal data in staging screens.
- **Assessment methodology:** the cloud model is directed by a baked-in methodology grounded in the OWASP MASVS v2 control groups and MASTG testing approach, mapped to the six on-device collectors. The app does not fabricate control IDs, CVEs, or scores; model suggestions remain explicitly unverified hypotheses. Currency of the methodology beyond this baseline comes from the capable model you select.
- **Live advisories (optional toggle):** when enabled with an HTTPS feed URL, the controller app performs one bounded fetch of that feed before launch and hands the sanitized text to the model as explicitly untrusted reference data. This is the controller's own egress to the advisory host — it is outside the target-UID scoped firewall and does not weaken that containment, but it does mean the controller contacts an additional host; the report records that live advisories were enabled. The fetch is fail-open: a failure is logged and the assessment continues without external reference.
- Use a finite maximum of 1–100 steps. The initial phase is labelled baseline/no target-code hooks; root-intervention observations are labelled as privileged-device evidence, not ordinary-attacker proof.

The assessment supports owner user 0 only. It rejects system, shared-UID and controller/self targets. Rooting does not make this a trusted device: root or a compromised OS can observe/alter app data, traffic, behavior and evidence despite app-level encryption and restrictions.

## Coverage and limitations

Six bounded checks are supported: `manifest` (installed manifest/configuration, requested permissions and exported components), `storage` (bounded root-readable path observations), `logs` (bounded target-process logs), `network` (target UID socket/firewall observations), `screenshots` (local target screenshots), and `coverage` (visited-screen/collector coverage). Each check can be unavailable or incomplete; absence of a reported issue is not proof of safety. Observed configuration or root-readable data is not by itself a confirmed vulnerability.

This is not deep code analysis, TLS interception/decryption, runtime TLS/crypto instrumentation, decrypted traffic inspection, exhaustive UI exploration, or cross-account authorization testing. It cannot establish backend authorization without dedicated controlled accounts. Hostname-to-IP pinning has the shared-CDN/IP, DNS-change and isolated-process constraints above. Model-generated `REPORT_HYPOTHESIS` entries are finite-exploration suggestions supported by recorded observations, explicitly unverified and kept separate from deterministic collector findings; they are not vulnerability confirmations.

## Running, recovery, and evidence

The app's foreground assessment controller exposes pause, stop and resume. Resume starts with fresh observation and does not replay an interrupted pending mutation. Process interruption marks a running session paused and requires recovery of its owned stale network restriction before resuming. Use **Recover stale network restriction** when indicated; cleanup is scoped to this app's owned rules. End/stop an assessment and complete cleanup before uninstalling the app or clearing its data, or its persisted ownership state needed for recovery may be lost. Do not clear data/uninstall to bypass cleanup.

While the controller UI is visible it sets `FLAG_KEEP_SCREEN_ON`; an assessment also takes a bounded wake lock. Neither mechanism bypasses PIN/keyguard, reboot, or a user's manual device lock. Keep the device unlocked and observe it during assessment; a lock or external intervention can pause/refuse actions.

Reports can be exported by the user as Markdown (including embedded JSON). Screenshot evidence is stored in the app-private viewer area, not exported automatically; retained evidence is limited to five PNGs, each at most 20 MB. Transient model screenshots are separately rotated. App-private storage and Keystore protection do not defend against a rooted OS. Review reports/screenshots before sharing.

Each session also keeps a verbose, append-only process log (`assessment/logs/<id>.jsonl`) covering lifecycle transitions, collector outcomes, errors, and the sanitized model request/response payloads. Every line is re-sanitized with the current secret set before it is written. Review it in-app with **View session log** and export it per session as Markdown with **Export session log**. The log is size-bounded and secret values are redacted, but it still contains sanitized model I/O and should be reviewed before sharing; it is not a defense against a rooted OS.

Host UiAutomator2 automation may suppress accessibility services. The instrumentation test cycles only this app's already-enabled accessibility service to rebind it after process reset; enable it first in Android Settings. This does not grant accessibility or root automatically.

## Development verification

The repository's build, lint and JVM tests have passed. On a rooted (Magisk) Android 12 device, the full instrumentation suite (five tests, including `AssessmentSmokeTest`) has passed repeatedly: real collectors, accessibility tap/text/credential actions on the controlled target, the `SessionController` loop driven by the deterministic test-only model adapter, retained screenshot evidence, the verbose per-session log (captured, records completion, leaks no secrets), and report/persistence leak checks.

Provider selection (OpenAI-compatible and Anthropic), live model-list fetch, and the live-advisory fetch require user-supplied API keys and an authorized target; they are exercised by JVM tests at the policy/persistence level but not by the deterministic device smoke, which uses a test-only model adapter. This is not a live cloud staging assessment; a live cloud-driven assessment has not been demonstrated. See `docs/design.md` and `docs/implementation-plan.md` for architecture and API details.
