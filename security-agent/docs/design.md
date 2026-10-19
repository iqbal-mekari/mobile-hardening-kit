# Device-resident security assessment agent

## Approved intent

A standalone Android application inside this repository assesses authorized staging Android apps from installed APKs, without target source code or a host computer during execution. A rooted phone executes the assessment; a cloud model reasons over sanitized observations. The user supplies dedicated test credentials and permits staging test-data mutation. This project is separate from mobile_hardening_kit and does not alter its API or enforcement-free behavior.

## Architecture

- Android framework Activity: session configuration, secret entry, root/accessibility setup, progress, pause/resume/stop, findings and document export.
- User-started foreground service: one assessment worker, persisted checkpoints, explicit interruption and recovery. No automatic reboot execution. Recovery never blindly replays a potentially mutating action.
- Cloud client: configurable OpenAI-compatible HTTPS chat-completions endpoint and model. API key stored with Android Keystore AES/GCM. No provider-specific credentials are bundled.
- Agent loop: observe, request a structured action, apply local policy, execute, record evidence, repeat until completion, intervention, failure, or a configured step bound.
- Accessibility executor: inspect and act on fresh target-app nodes, set Unicode text and credentials without shell interpolation, scroll and navigate. Password-node contents are omitted.
- Root helper: only internal, fixed-purpose commands for capability detection, screenshots, bounded evidence reads and per-target network restriction. No shell action in the model protocol and no remotely accessible control port.
- Check engine: installed APK/manifest metadata, exported Android surface, storage observations, bounded target logs, network socket observations, screenshot exposure and explicit collector coverage. Findings distinguish configurations, observations and verified impact. Root-only access never proves an unprivileged exploit.
- Network scope: fail-closed IPv4 and IPv6 owner-UID firewall rules for a dedicated target UID and exact configured staging hosts resolved before launch. No wildcard hosts or redirect-driven scope expansion. Document DNS/address/CDN and shared/isolated-process limitations. Never flush unrelated rules. Remove only this app's chain on normal exit and offer recovery of a stale restriction after interruption.
- Reports: local JSON session record and human-readable Markdown, including app/version, action history, finding severity and confidence, attacker prerequisites, baseline/intervention labels, collector failures, unsupported checks and incomplete coverage.

## Data and trust

The target app and every observation are untrusted. They cannot change system policy, request secrets, choose arbitrary commands or expand scope. The model may reference username/password identifiers, not resolved values. API keys and credentials must be excluded from observations, histories, exception messages and reports. Raw screenshots never go to the model unless the user explicitly opts in for that session; text observations also require cloud-disclosure consent. Report export is user initiated through the Android document picker. App backup is disabled.

## Operational boundaries

The initial launch is baseline with no target-code hooks; network restriction and root observations are disclosed. Interactive exploration is recorded separately. A collector not available on this device is recorded as unavailable. The app does not claim desktop scanner parity, runtime TLS/crypto hook coverage, backend authorization coverage without controlled accounts, exhaustive UI coverage, or a clean bill of health. MFA, CAPTCHA, external login apps, root refusal, denied accessibility, failed firewall installation and unresolvable destinations lead to explicit pause/failure rather than invented success. No purchases, real messaging or destructive production operations are authorized by this staging-only design.

## Verification

The standalone project uses Kotlin 1.9.22, AGP 8.2.2, Gradle 8.2.1, JDK 17 and Android SDK 34. The earlier repository-convention Kotlin 1.8.22, AGP 7.3.0 and Gradle 7.6.3 pins were tried, but AGP 7.3 lint could not analyze the Kotlin 1.8 metadata emitted by the new Kotlin bytecode. This project-only toolchain update fixes that compatibility mismatch; existing plugin projects remain unchanged. Behavioral tests cover policy boundaries, strict model-action decoding, secret redaction, state transitions and interruption. On the connected rooted device, install and open the actual app, exercise configuration and prerequisite failures, execute deterministic collectors and an agent-loop smoke with a clearly identified controlled model adapter where needed, observe the actual UI and export an actual report. A live cloud-driven target assessment requires the user's endpoint/model/key and authorized staging target; never substitute a fixture for that claim.
