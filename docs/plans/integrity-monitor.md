# Runtime integrity monitor and split event streams (0.4.0)

Branch: `feat/integrity-monitor` (stacked on `feat/screen-protection-redesign`; rebase onto `main` after PR #3 merges) · Target release: `0.4.0` · Status: implemented on branch (Phases 0–5, T, review fixes); Android device-verified on API 32; release pending

## 1. Goal

Integrity checks (Frida, Xposed/LSPosed, root/jailbreak, debugger) run today only when the host app calls `snapshot()`. A tool that attaches after that call (Frida attach mode, a debugger) stays invisible until the next call. This release:

1. Adds an **opt-in runtime integrity monitor** that re-checks on a schedule matched to when each tool can enter the process, and pushes only new, changed, or cleared findings.
2. **Splits the event stream** so capture/display events and integrity findings have separate subscriptions, lifecycles, and costs.
3. **Hardens the detectors** where research found dead or weak checks, without adding native (NDK) code or third-party dependencies.

The kit stays report-only: it never blocks, kills, or calls anti-debug APIs (`ptrace(PT_DENY_ATTACH)` etc.).

## 2. Decisions (approved 2026-10-28)

| # | Decision | Rationale |
|---|---|---|
| D1 | Two event streams: `screenEvents` (screenshot, capture, external display) and `integrityEvents(config)` (monitor). Separate EventChannels; subscribing to one never starts the other's native work. One shared `HardeningSignal` schema. | Different consumers (UI vs telemetry), lifecycles (window vs process), costs (OS callbacks vs polling), and semantics (moments vs states needing diffing). |
| D2 | Non-breaking: `stream` becomes a `@Deprecated` alias of `screenEvents` in 0.4.0, removed in 0.5.0. PR #3 / 0.3.0 is not touched. | Keeps 0.3.0 verification and tagging independent of this work; pre-1.0 deprecation for one minor release is enough for our consumers. |
| D3 | Check schedule follows injection timing (§5.1): process-start tools are checked at start and on resume; runtime-attach tools are also checked on an interval and, on iOS, on dyld image load. | Polling LSPosed is wasted work (it can only enter at fork); missing a Frida attach is the actual gap. |
| D4 | No new signal types. New evidence maps to existing `instrumentation` / `debuggerAttach`; metadata gains `techniques` and monitor fields (§4.3). | Older Dart decoders throw `FormatException` on unknown types (`lib/src/hardening_signal.dart:31-35`); avoids a lockstep upgrade. |
| D5 | Pure Kotlin / Swift only. NDK-based checks (inline-hook prologue diff, `ArtMethod` entrypoint checks, raw-syscall `/proc` reads) are a separate decision, not in 0.4.0. | Adds a native toolchain, ABI matrix, and per-OS-version fragility to a dependency-light kit. |
| D6 | No `INTERNET` permission. The Frida port probe via `/proc/net/tcp` runs only on API ≤ 28; no active `connect()` probe. | `/proc/net` is closed to apps from Android 10 (verified on API 32; Android 10 privacy changes). A library must not merge `INTERNET` into consumer manifests for a heuristic. |
| D8 (added 2026-10-28) | 0.4.0 adopts the internal Flutter 3.47.8 toolchain baseline (2026): Flutter 3.47.8, Dart 3.13.7 (package floors `flutter >=3.47.8`, `sdk >=3.13.7 <4.0.0`), Gradle 9.1.0, AGP 9.0.1, Kotlin 2.3.20, build JDK 17, Android minSdk 24, iOS 15.0, exact dependency pins (only SDK constraints may be ranges), `.fvmrc` pinned to 3.47.8 in every Flutter project. | Org-wide toolchain baseline; Dart 3.13.7 fixes a TLS MITM advisory (GHSA-frr6-h895-5pxp, per the guide). minSdk 24 and the toolchain floors are breaking for consumers. |
| D7 | LSPosed is reported only through a low-confidence heuristic (`artSegments`, §5.2), documented as verified on one device; no "LSPosed detection" claim. Java-side `Class.forName` Xposed probes are dropped. | Phase 0 (§11): with a module loaded, LSPosed 1.9.2 leaves no name in maps/threads/fds/mountinfo/environ and hides `XposedBridge` from `Class.forName` on both loaders; only libart's text-segment split was observed. |

## 3. Non-goals

- Blocking, crashing, or degrading the app on detection; anti-debugging or anti-tamper countermeasures.
- Defeating a determined attacker: once Frida is attached it can hook the detector itself. Runtime checks are a race (§6); the server-side story is consumer responsibility (documented guidance only).
- Native-code detectors (D5) and new third-party dependencies.
- Background monitoring while the app is not in the foreground.

## 4. Public API

### 4.1 Dart

```dart
/// Screenshot, capture, and external-display events (replaces `stream`).
Stream<HardeningSignal> get screenEvents;

@Deprecated('Use screenEvents; removed in 0.5.0')
Stream<HardeningSignal> get stream => screenEvents;

class IntegrityMonitorConfig {
  const IntegrityMonitorConfig({
    this.interval = const Duration(seconds: 30), // ASSUMPTION: tuned in Phase 0
    this.checkOnResume = true,
  });
  /// Runtime-attach checks while in the foreground; clamped to [5 s, 24 h].
  final Duration interval;
  final bool checkOnResume;
}

/// Runs the monitor while subscribed. First pass reports every current finding
/// as `detected`; later passes report only `detected` / `changed` / `cleared`.
Stream<HardeningSignal> integrityEvents([IntegrityMonitorConfig config = const IntegrityMonitorConfig()]);

/// Runs one monitor pass now (e.g. before a sensitive action); results arrive
/// on `integrityEvents` with `trigger: manual`. No-op when not monitoring.
Future<void> checkIntegrityNow();
```

`expectedSigningCertificateSha256` and `trustedAccessibilityPackages` continue to come from the `MobileHardeningKit` instance and apply to monitor passes. `snapshot()` is unchanged.

Both getters return a single cached broadcast stream per kit instance (fixes today's per-access `receiveBroadcastStream()` where a second listener re-subscribes natively and cancelling either one stops both; ASSUMPTION on exact Flutter re-listen behaviour, covered by a test). `integrityEvents` with a different config while subscribed is a `StateError`.

### 4.2 Native core API (Kotlin / Swift mirror)

- `startObserving` / `stopObserving` keep their names and now cover screen events only (no behaviour change).
- New `startMonitoring(config, listener)` / `stopMonitoring()` / `checkIntegrityNow()`, implemented in a new `IntegrityMonitor` type that owns scheduling and diffing and reuses the detectors behind `snapshot()`.

### 4.3 Channel and event contract

- EventChannel `mobile_hardening_kit/events` stays as the screen-events channel (internal name unchanged).
- New EventChannel `mobile_hardening_kit/integrity_events`; listen arguments `{intervalMs, checkOnResume}`.
- New method `checkIntegrityNow` (no args, returns null).
- Integrity event metadata = the `snapshot()` metadata for that type plus:
  - `change`: `detected` | `changed` | `cleared` (a cleared event carries the last known metadata).
  - `trigger`: `start` | `resume` | `interval` | `imageLoad` (iOS) | `manual`.
  - `techniques`: list of evidence sources: `maps`, `threadName`, `tracerPid`, `memfdExec`, `anonRwx`, `artSegments`, `mountinfo`, `port` (Android); `dyldImage`, `dyldImageLoad`, `pTraced` (iOS).
- Diff key: signal type + sorted `techniques` + sorted `artifacts`; timestamps excluded.
- Screen-event schema alignment: iOS `screenshotTaken` gains `source: "userDidTakeScreenshotNotification"` (keeps `active` for compatibility); iOS `observedAt` gains milliseconds to match Android.

### 4.4 Contract details (binding for all implementers)

**Native config and API**
- Kotlin: `data class IntegrityMonitorConfig(val intervalMs: Long = 30_000, val checkOnResume: Boolean = true)`; effective interval clamped to `[5_000, 86_400_000]` ms (5 s to 24 h). `MobileHardeningKit.startMonitoring(config: IntegrityMonitorConfig, listener: HardeningSignalListener, hardeningConfig: HardeningConfig = HardeningConfig())`, `stopMonitoring()`, `checkIntegrityNow()`. Main thread; passes run on one background executor; results delivered on the main thread. Starting while monitoring replaces the previous session (stop, then start).
- Swift: `public struct IntegrityMonitorConfig { public var interval: TimeInterval = 30; public var checkOnResume = true }` (effective interval clamped to [5 s, 24 h], NaN → 5 s); `startMonitoring(_ config: IntegrityMonitorConfig = .init(), handler: @escaping (HardeningSignal) -> Void)`, `stopMonitoring()`, `checkIntegrityNow()`. Same replace semantics.

**Channel**
- EventChannel `mobile_hardening_kit/integrity_events`; listen args `{intervalMs: int, checkOnResume: bool, expectedSigningCertificateSha256?: String, trustedAccessibilityPackages: [String]}` (iOS ignores the last two). Method `checkIntegrityNow` → null. Missing/invalid args → defaults.

**Passes and tiers**
- `full` tier = every `snapshot()` detector **except** the screen/display types `screenCaptureActive` and `externalDisplay`, which belong to `screenEvents` only (amended 2026-10-28 after Phase 2/3 both diffed them). `runtime` tier = `instrumentation` + `debuggerAttach` only.
- `start` (full) on subscribe; `resume` (full) when the app returns to the foreground if `checkOnResume`; `interval` (runtime) while foregrounded; `manual` (full) from `checkIntegrityNow()`; iOS `imageLoad` (instrumentation only).
- Diffing compares only the types the pass covers: a runtime pass never clears `root`. Key = type + sorted `techniques` + sorted `artifacts`. Same key → nothing emitted; different key → `changed`; new type → `detected`; type gone → `cleared` (with the last metadata). The first pass emits every finding as `detected`.

**Metadata** (`snapshot()` also gains `techniques` on these types)
- `instrumentation` (Android): `artifacts` (≤ 8 × 120 chars; maps paths and `thread:<name>` entries), `tracerPort` (API ≤ 28, else 0), `anonRwxCount`, `artTextSegments`, `techniques`. Reported only when a primary technique hits (`maps`, `threadName`, `memfdExec`, `artSegments`, `port`); `anonRwx` is supporting only.
- `debuggerAttach` (Android): `debuggerConnected`, `tracerPid` (bool), `techniques` ⊆ {`jdwp`, `tracerPid`}. iOS: `traced: true`, `techniques: [pTraced]`.
- `root` (Android): existing keys + `mountMarkers` (≤ 8), `techniques` ⊆ {`paths`, `buildTags`, `managerPackage`, `mountinfo`}. `jailbreak` (iOS): existing keys + `techniques` ⊆ {`paths`, `urlSchemes`}.
- iOS `instrumentation`: `artifacts`, `techniques` ⊆ {`dyldImage`, `dyldImageLoad`}.
- Monitor events add `change` and `trigger` (§4.3).

## 5. Platform mapping

### 5.1 When each tool enters the process

| Tool | Enters | Mid-run attach | Schedule |
|---|---|---|---|
| Frida attach (frida-server) | any time; ptrace inject then detach (source: frida-core `frida-helper-backend.vala`) | yes | start + resume + interval (+ iOS image load) |
| Frida spawn / Gadget | process start | no | start + resume |
| LSPosed (Zygisk/Riru), Xposed, Zygisk modules | before app specialization (source: Magisk docs) | no | start + resume |
| Magisk / KernelSU / APatch, jailbreak | device state before launch | rare (ASSUMPTION) | start + resume |
| Debugger (JDWP, ptrace, lldb) | any time | yes | start + resume + interval |
| Emulator, signature, dev settings, accessibility | device/app state | settings can change | start + resume |

Interval passes run only the runtime-attach tier (instrumentation + debugger) to bound cost; start/resume/manual passes run the full set.

### 5.2 Android (`native/android/core`)

| Change | Detail | Evidence |
|---|---|---|
| Thread-name scan (`threadName`) | `/proc/self/task/*/comm`; report on `gum-js-loop` or `pool-frida`; `gmain` / `gdbus` are generic GLib names, listed as artifacts only alongside a primary hit. Remove `gum-js-loop` from the maps terms. | Verified (§11): attach and spawn add exactly `gum-js-loop`, `gmain`, `gdbus`, `pool-frida`; gone after detach |
| `TracerPid` (`tracerPid`) | non-zero → `debuggerAttach`. Not a Frida signal. | Verified: Frida's ptrace shows for ~0.2–0.4 s at attach only (2 of ~120 samples at 0.1 s) |
| Executable memfd (`memfdExec`) | `/memfd:` mapping with `x` permission, private (`p`), name not `jit-cache` | Verified: clean baseline has only shared `r-xs /memfd:jit-cache`; Frida agent is `r-xp /memfd:frida-agent-64.so`; with an LSPosed module loaded a private `r-xp /memfd:jit-cache` appears, hence the name exclusion |
| Anonymous RWX (`anonRwx`) | count of unnamed `rwxp` mappings > 0; supporting evidence only, never reported alone as Frida | Verified: 0 at baseline/control, 3–6 with Frida, 3–5 **remain after detach**. WebView/JS-engine false positives untested (§10) |
| ART text split (`artSegments`) | number of `r-xp` segments of `libart.so` > 1 → `instrumentation` (low confidence, "ART hooked") | Verified on API 32 only: 1 → 15 with an LSPosed module loaded, back to 1 when disabled. Other hookers (e.g. Frida Java bridge) may also split it (inference) |
| Magisk/Zygisk mounts (`mountinfo`) | `/proc/self/mountinfo` markers (`magisk`, `zygisk`, `/adb/modules`) → `root`; start/resume tier only (1139 lines) | Verified readable (run-as) and present on the rooted device, including for unscoped apps; DenyList-unmounted apps untested |
| Narrow maps terms | `gadget` → `frida-gadget`; keep `substrate` / `libhooker` as low-signal; keep `frida`. Hook terms are matched on the mapped **file name** (last path component) only, with specific tokens, never on the directory path; `artifacts` hold file names only (≤ 120 chars), not full paths | `frida-agent` maps match verified; `gadget` too broad (inference). Review fix: a directory or app name containing a term (e.g. `TGIFridays.app`) must not match, and container paths are quasi-identifiers |
| Port probe | `/proc/net/tcp` only on API ≤ 28 (D6) | Denied on API 32 (verified) |
| ~~Legacy Xposed probes~~ | dropped (D7) | Verified: `ClassNotFoundException` on app and system loaders with an LSPosed module loaded; no xposed frames in stack traces |
| Threading | monitor passes on a single background executor, results posted to the main thread; the one-shot snapshot also runs off the main thread in the Android adapter | `/proc` reads on main thread risk jank/StrictMode (inference) |
| Lifecycle | interval paused when the attached activity stops; resume pass on start; the monitor starts paused when no activity is attached and runs once one attaches | uses existing `attachActivity` / `detachActivity` |
| Test seams | extend `FileAccess` with `list(dir)`; injectable scheduler and clock | Robolectric + `ShadowLooper` |

### 5.3 iOS (`ios/Classes/Core`)

| Change | Detail | Evidence |
|---|---|---|
| dyld image-load observer | `_dyld_register_func_for_add_image` registered **once per process** (no unregister API), **from a background queue** (replay is synchronous on the registering thread, ~30 ms for ~600 images), gated by an atomic enabled flag and a weak sink. Callback does only `dladdr` + `strrchr`/`strcasestr` on C strings against a needle table built eagerly (before registration, so no lazy init or allocation under the loader lock), enqueues hits to a private serial queue, emits `trigger: imageLoad`. | Simulator-measured (§11): synchronous full replay before the call returns; a second registration replays again; live callbacks run on the `dlopen` caller's thread (can be main); `dladdr` gives absolute paths; no deadlock calling dyld APIs inside |
| Replay de-dup | a header address in a snapshot taken just before registration is replay and belongs to the `start` pass; any other header is live (`imageLoad`), even if a `dlopen` on another thread lands before the register call returns. Images loaded between the snapshot and the registration are replayed but reported live (they did load after observation began). Fixes the earlier flag-flip gap (review L3) | Simulator-measured replay; snapshot is a bounded header-pointer list, linear scan under the lock |
| Interval/resume | `P_TRACED` + image-name scan + jailbreak paths (resume) | Existing detectors |
| `DYLD_INSERT_LIBRARIES` | not implemented (Phase 0: unset; low value) | Inference; likely stripped for signed apps |
| Narrow terms | matched case-insensitively on the **last path component** (file name) only, never the directory or app bundle name, with specific tokens: `fridagadget`, `frida-gadget`, `frida-agent`, `libfrida`, `mobilesubstrate`, `cydiasubstrate`, `libsubstitute`, `substitute-loader`, `ellekit`, `libhooker`. `xposed` is dropped on iOS (Android-only). The polling scan uses the same rule. Artifacts are the lowercased file name only (≤ 120 chars) | Review fix: a bare `frida` matched `TGIFridays.app` and every file inside it; container paths hold the app UUID (quasi-identifier) |
| Cheaper scans | C-string matching instead of allocating/lowercasing every image name; `hasCodeSignature()` reads header + load commands only | Simulator-measured: C-string pass 1.2–3 ms vs 3–48 ms for the current String approach (554–627 images) |
| Lifecycle | interval paused while not active; resume pass on `didBecomeActive` | existing notifications |
| Test seams | `HardeningProbe` gains `observeImageLoads` and an injectable timer | hostless XCTest |

Open on iOS: whether Frida's attach-mode agent appears in the dyld image list or fires the callback (custom loader?) is **unverified** and needs a jailbroken device.

## 6. Risk register

| Risk area | Risk | Mitigation |
|---|---|---|
| Detection evasion | Attached Frida can hook `/proc` reads, `sysctl`, `dladdr`, or the monitor itself; renamed agents/ports evade name matching | Documented as a race; README guidance: report to backend, treat missing heartbeats as suspicious, tighten interval on sensitive screens |
| False positives | memfd/JIT and WebView executable mappings; Xcode/`debugserver` sets `P_TRACED`; legit SDK swizzling | memfd check gated on Phase 0 baseline; no swizzle/symbol-hook checks in 0.4.0; `techniques` lets consumers weight evidence |
| Performance / battery | Interval scans of maps (hundreds of lines), thread lists, dyld images | Runtime tier only on interval; foreground only; interval clamped to [5 s, 24 h]; Phase 0 per-pass timing on POCO F1 and simulator |
| Platform stability | dyld callback runs under a loader lock; heavy work inside can deadlock | Copy-and-enqueue only; no ObjC/Swift allocation-heavy work, UIKit, or logging inside the callback |
| Lifecycle | Single listener slot per core; shared teardown; adapter detach must cover the new channel | Separate `IntegrityMonitor` object with its own listener; adapter tests for teardown of both channels |
| Privacy (UU PDP) | Findings forwarded to a backend may become personal data when linked to a user | Data minimisation kept: artifact lists capped at 8 × 120 chars, file names only (no directories), own-process images only, no device identifiers added; README note for consumers |
| App Review | dyld add-image callback | Public, non-deprecated header API; ASSUMPTION low rejection risk |
| Compatibility | Dart enum strictness | D4: no new types |

## 7. Phases

### Phase 0 — Device and simulator spikes (gate for Phases 2–3)

Android, POCO F1 (Android 12/API 32, Magisk, LSPosed 1.9.2, Frida 17.18.0). ARTEMIS is not connected in this session, so Phase 0 is driven with `adb` (root `su` reads of the app's `/proc/<pid>` for ground truth). In-app readability of each source from the real `untrusted_app` domain is confirmed when the detectors run on device in Phase 2. Probes:
1. Frida attach: exact thread names in `task/*/comm`, `TracerPid` during and after injection, `/proc/self/fd` targets, maps entries.
2. Clean baseline (with and without a WebView): count of executable `/memfd:` and anonymous mappings.
3. LSPosed with the no-hook probe module: `Class.forName` XposedBridge results, stack frames, maps/mountinfo differences, to find any verifiable LSPosed signal.
4. Per-pass timing of the full and runtime tiers.

iOS, simulator (Xcode 27): add-image replay and `dlopen` firing, callback thread, re-registration duplication, image count and scan cost. Jailbroken-device and Gadget items are listed in §10.

Exit: findings appended to §11; any failed assumption changes §5 before implementation.

### Phase 1 — Dart contract

`screenEvents`, deprecated `stream`, cached broadcast streams, `IntegrityMonitorConfig`, `integrityEvents`, `checkIntegrityNow`. Tests: multi-listener sharing, cancel semantics, config `StateError`, decoding of new metadata. Gate ≥95% lines.

### Phase 2 — Android core

Detectors per §5.2, `IntegrityMonitor` (scheduler, diffing, tiers, lifecycle pause), schema metadata. Robolectric tests across SDK 23/28/29/32/35. Gates ≥95% lines / ≥80% branches.

### Phase 3 — iOS core

Detectors per §5.3, `IntegrityMonitor`, single-registration image-load observer, schema alignment. XCTest on iOS 18.6 / 26.4 / 27.0 simulators; add new files to the `check_xccov.py` loop in `.github/workflows/ci.yml` (≥95%). `swift-format lint --strict`.

### Phase T — Toolchain upgrade (D8)

- `pubspec.yaml` (package + example): SDK floors per D8; exact dev-dependency pins; `fvm use 3.47.8` in the root and `example/flutter` (`.fvmrc` committed, `.fvm/` ignored).
- Android (`native/android`, `android/`, `example/flutter/android`, `example/android`): Gradle 9.1.0 wrappers, AGP 9.0.1, Kotlin 2.3.20, JDK 17, minSdk 24; follow the AGP 9 migration (built-in Kotlin, DSL changes) from official Android docs; Robolectric/Jacoco versions verified on Maven Central, never guessed.
- iOS: Flutter 3.47.8 with Xcode 27; drop the `FLUTTER_XCODE_ARCHS` workaround if no longer needed; migrate the example to the UIScene lifecycle if Flutter 3.47.8 supports it (fixes the iOS 27 simulator crash noted in PR #3).
- CI: Flutter 3.47.8, JDK 17. Docs: requirements in README, AGENTS.md, CHANGELOG.
- Gates: every existing CI gate re-run green on the new toolchain, including the `apk --release` build that could not run locally on 3.24.

### Phase 4 — Adapters

Second EventChannel and `checkIntegrityNow` in `android/.../MobileHardeningKitPlugin.kt` and `ios/Classes/MobileHardeningKitPlugin.swift`; engine-detach teardown of both channels. Tests: Android adapter (≥95% / ≥60%), `example/flutter/ios/RunnerTests` (≥90%).

### Phase 5 — Samples, docs, policy

- Flutter example: monitor toggle, interval, live findings list, "check now".
- README: timing table (§5.1), monitor API, `techniques` vocabulary, limits (race, LSPosed gap, `/proc/net` on Android 10+), backend guidance, migration `stream` → `screenEvents`.
- AGENTS.md: two-stream rule, no-new-type rule (D4), report-only monitor, no NDK/INTERNET without a decision.
- CHANGELOG `[Unreleased]`: Added / Changed / Deprecated.
- Native samples move after the 0.4.0 tag (per AGENTS.md).

### Phase 6 — Verification and release 0.4.0

Re-run Phase 0 on the release candidate (Android with Frida attach mid-session and LSPosed; iOS per §10 devices). Requires 0.3.0 tagged first. Tag `0.4.0` only after user approval.

## 8. Migration (0.3.x → 0.4.0)

| 0.3.x | 0.4.0 |
|---|---|
| `kit.stream.listen(...)` | `kit.screenEvents.listen(...)` (`stream` still works, deprecated) |
| Periodic `snapshot()` in app code | `kit.integrityEvents(IntegrityMonitorConfig(interval: ...)).listen(...)`; keep `snapshot()` for one-off reads |
| `snapshot()` before a sensitive action | unchanged, or `checkIntegrityNow()` while monitoring |

## 9. Execution and delegation

| Work | Model tier | Mode |
|---|---|---|
| Phase 0 Android device spikes | Sonnet with adb/Frida (ARTEMIS when reconnected) | sequential; one device |
| Phase 0 iOS simulator spike | Sonnet | background, parallel with Android |
| Phase 1 Dart contract | Sonnet | after Phase 0 |
| Phase 2 Android core | Sonnet | parallel with 3 |
| Phase 3 iOS core (dyld callback, locking) | Opus | parallel; concurrency-sensitive |
| Phase T toolchain upgrade | Opus | parallel with Phase 3; before Phase 4 |
| Phase 4 adapters + Phase 5 samples | Sonnet | after 1–3 and T |
| Docs drafts | Haiku draft, orchestrator review | after 4 |
| Final cross-platform security review | Opus | before PR |

## 10. Open questions and untested coverage

Resolved 2026-10-28: D2 approved (deprecate `stream` in 0.4.0); default interval 30 s, revisited only if Phase 0 cost numbers demand it; newer and jailbroken devices skipped for now.

**Untested coverage (no device available; must stay listed in README limits and the PR until verified):**

| Area | Not verified | Needs |
|---|---|---|
| Android API 23–28 | `/proc/net/tcp` port probe, legacy behaviour | API ≤ 28 device |
| Android API 33–35 | monitor and detectors on newer SELinux policy; thread/maps/status readability | Android 13/14/15 device |
| iOS Frida attach / spawn (frida-server) | agent visibility in the dyld image list and add-image callback; image name | jailbroken iPhone (Dopamine/palera1n) |
| iOS Frida Gadget | load-command / renamed Gadget detection | re-signed build on a physical iPhone |
| iOS jailbreak tweak runtimes | ElleKit / libhooker / Substitute image names | jailbroken iPhone |
| iOS `P_TRACED` on device | Xcode attach/detach transitions (simulator lldb attach verified) | physical iPhone |
| Android false positives | `memfdExec` / `anonRwx` with WebView or JS engines; `artSegments` on other API levels, ROMs, and with other hookers | WebView test app; other devices |
| Android classic Xposed / EdXposed, Frida Gadget (repackaged APK), Magisk DenyList | no setup on the device | dedicated test setups |
| Android `trigger: manual` on a real change | observed only without a change (no duplicates); the interval pass won the race | rerun with a 30 s interval |
| Release-build cost; Android ≠ 12 | cost measured on a debug build only | release build; other devices |

Resolved by Phase 0: `memfdExec` ships with the `jit-cache` name exclusion (clean baseline); `mountinfo` ships in the `root` start/resume tier.

Still open:
1. NDK detectors (D5): schedule a separate research/decision record?

## 11. Implementation notes

### Phase 0 findings (2026-10-28)

**Android — POCO F1, Android 12/API 32, Magisk, LSPosed 1.9.2 (Zygisk), Frida 17.18.0.** Captured as root from `/proc/<pid>` of `com.mekari.mobile_hardening_kit_example`; evidence kept outside the repo (session scratchpad `phase0-android/evidence/`). All rows verified on device.

| Scenario | Threads | Maps | Other |
|---|---|---|---|
| Baseline (LSPosed active, nothing scoped) | ART/Flutter/Binder only | memfd only `jit-cache` (`r--s`, `r-xs`, `rw-s`); exec anon: `[anon:dart-code]`, `jit-zygote-cache`, `[vdso]`; 0 unnamed `rwxp` | TracerPid 0; 125 fds; mountinfo shows device-level Magisk/Zygisk/LSPosed bind mounts |
| Frida attach | + `gum-js-loop`, `gmain`, `gdbus`, `pool-frida` | + 9 lines `/memfd:frida-agent-64.so` (7 `r-xp`); + 3–6 unnamed `rwxp` | TracerPid = frida-server pid for ~0.2–0.4 s at attach, then 0; + sockets/eventfds |
| 5 s after detach | Frida threads gone | agent memfd gone; 3–5 unnamed `rwxp` remain | TracerPid 0; fds back to baseline |
| Frida spawn (+4 s) | same four threads | same agent memfd; 4 unnamed `rwxp` | TracerPid 0 |
| LSPosed module loaded (scoped to the example) | + `onPool-worker-1` (unattributed) | no lsposed/xposed/lspd/zygisk names; `libart.so` `r-xp` segments 1 → 15; + private `r-xp /memfd:jit-cache` | `Class.forName` of `XposedBridge`, `org.lsposed.lspd.*`, `io.github.libxposed.api.*` → `ClassNotFoundException` on app and system loaders; classes exist in a hidden loader (enumerable only via Frida); no xposed stack frames |
| Module disabled (control) | as baseline | `libart.so` 1 segment | — |

Notes: LSPosed Manager (parasitic) launches with `am start -c org.lsposed.manager.LAUNCH_MANAGER -n com.android.shell/.BugreportWarningActivity`. Frida 17 needs `frida-java-bridge` compiled into scripts for Java probes.

**iOS — simulators 18.6 and 27.0 (Xcode 27).** Simulator-measured only; device dyld cache differs.

- `_dyld_register_func_for_add_image` replays all loaded images (554 / 626) synchronously on the registering thread before returning (~27–31 ms with `dladdr`); a second registration replays again for the new callback only.
- Later `dlopen` fires each callback once, before `dlopen` returns, on the caller's thread; `dlclose` fires the remove-image callback.
- `dladdr` in the callback returns absolute paths; calling `_dyld_image_count` / `_dyld_get_image_name` inside did not deadlock.
- Image scan: C-string `strcasestr` pass 1.2–3 ms median vs 3–48 ms for the current `[String]` + lowercase approach (host heavily loaded; ratios indicative).
- `P_TRACED` false under `xcodebuild test`; true while lldb is attached to a simulator process, cleared after detach (via `ps`). `DYLD_INSERT_LIBRARIES` unset.

Plan changes from these findings: §2 D7, §4.3 techniques, §5.2 and §5.3 tables, §10 untested coverage.

### Phase 6 device verification (2026-10-28, commit `979ca06`)

POCO F1, Android 12/API 32, app domain `u:r:untrusted_app` (SELinux enforcing), driven with adb through the example's monitor UI at a 5 s interval. Evidence kept outside the repo (session scratchpad `phase6-android/`).

| Scenario | Result |
|---|---|
| Clean start | `root` (`managerPackage`, `mountinfo`), `accessibilityUnrecognized`, `devModeEnabled`; no screen/display types, no `instrumentation` |
| Frida attach mid-run | `instrumentation` `detected`, `trigger: interval`, ~3 s after attach; techniques `maps`, `threadName`, `memfdExec`, `anonRwx` |
| Frida detach | `cleared` ~2 s after detach; a `changed` fired earlier while attached when `pool-frida` exited |
| Check now, no change | no event (no duplicates); `manual` on a real change not shown |
| Background ≥ 10 s | no interval events; `resume` pass reported the attach made while backgrounded |
| Frida spawn | caught on the `start` pass (no `pool-frida` thread in spawn mode) |
| LSPosed module scoped to the app | `instrumentation` with `artSegments` + `anonRwx`, `artTextSegments: 15`; gone when the module is disabled |

Per-pass cost (debug build, background thread, before the regex hoist): runtime tier median 114 ms / max 134 ms (n = 30); full tier median 197 ms / max 260 ms (n = 7).

### Security review (Opus, 2026-10-28) and fixes

No high findings. Fixed: file-name-only matching with specific tokens on both platforms (false positives on paths such as `TGIFridays`), interval clamp [5 s, 24 h] (Android `Long.MAX_VALUE` busy loop), Android monitor starts paused without an activity, Android Flutter `snapshot()` off the platform thread, per-call Dart integrity sessions (a second kit could drop the signing check), regex hoisting, file-name-only artifacts, activity unbind on destroy, eager dyld needles outside the loader lock, header-snapshot replay/live classification, Gradle `distributionSha256Sum` + wrapper validation in CI/release.

