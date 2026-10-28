**Classification: INTERNAL**

# Runtime integrity monitor and split event streams (0.4.0)

Branch: `feat/integrity-monitor` (stacked on `feat/screen-protection-redesign`; rebase onto `main` after PR #3 merges) · Target release: `0.4.0` · Status: approved 2026-10-28; Phase 0 in progress

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
| D7 | LSPosed coverage is **not claimed**. Java-side probes target legacy Xposed/EdXposed; LSPosed stays a documented gap until a technique is verified on device. | LSPosed 1.9.2 loaded a module into the example app on the POCO F1 and the current maps scan did not report it. |

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
  /// Runtime-attach checks while in the foreground; clamped to >= 5 s.
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
  - `techniques`: list of evidence sources, e.g. `maps`, `threadName`, `tracerPid`, `memfdExec`, `xposedClass`, `dyldImage`, `dyldImageLoad`, `port`.
- Diff key: signal type + sorted `techniques` + sorted `artifacts`; timestamps excluded.
- Screen-event schema alignment: iOS `screenshotTaken` gains `source: "userDidTakeScreenshotNotification"` (keeps `active` for compatibility); iOS `observedAt` gains milliseconds to match Android.

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
| Thread-name scan | `/proc/self/task/*/comm` for Frida thread names; move `gum-js-loop` here (it can never match a maps path) | Readability verified via run-as; **exact Frida thread names unverified**, Phase 0 |
| `TracerPid` | non-zero in `/proc/self/status` → `debuggerAttach` with `techniques: [tracerPid]` | Readable (verified); misses Frida after its detach (source-cited) |
| Executable memfd / anonymous mappings | flag `r-xp` `/memfd:` mappings excluding JIT caches | **False-positive baseline unverified** (ART JIT, WebView); ship only if Phase 0 baseline is clean |
| Narrow maps terms | `gadget` → `frida-gadget`; keep `substrate` / `libhooker` as low-signal | Inference: `gadget` is too broad |
| Port probe | `/proc/net/tcp` only on API ≤ 28 (D6) | Denied on API 32 (verified) |
| Legacy Xposed probes | `Class.forName("de.robv.android.xposed.XposedBridge")` via system and app class loaders; stack-frame check | Inference; LSPosed isolates its loader (D7) |
| Threading | monitor passes on a single background executor, results posted to the main thread | `/proc` reads on main thread risk jank/StrictMode (inference) |
| Lifecycle | interval paused when the attached activity stops; resume pass on start | uses existing `attachActivity` / `detachActivity` |
| Test seams | extend `FileAccess` with `list(dir)`; injectable scheduler and clock | Robolectric + `ShadowLooper` |

### 5.3 iOS (`ios/Classes/Core`)

| Change | Detail | Evidence |
|---|---|---|
| dyld image-load observer | `_dyld_register_func_for_add_image` registered **once per process** (no unregister API), gated by an atomic enabled flag and a weak sink. Callback does only `dladdr` + C-string match, enqueues hits to a private serial queue, emits `trigger: imageLoad`. | Header `mach-o/dyld.h` (Xcode 27 SDK): replays existing images at registration, no unregister (verified). Callback thread unverified |
| Replay de-dup | registration replay is treated as part of the `start` pass, not separate `imageLoad` events | Inference |
| Interval/resume | `P_TRACED` + image-name scan + jailbreak paths (resume) | Existing detectors |
| `DYLD_INSERT_LIBRARIES` | `getenv` check at start | Inference; likely stripped for signed apps, low value |
| Narrow terms | `substrate` → `mobilesubstrate` / `cydiasubstrate`; add `fridagadget` | Inference |
| Cheaper scans | C-string matching instead of allocating/lowercasing every image name; `hasCodeSignature()` reads header + load commands only | Inference; cost measured in Phase 0 |
| Lifecycle | interval paused while not active; resume pass on `didBecomeActive` | existing notifications |
| Test seams | `HardeningProbe` gains `observeImageLoads` and an injectable timer | hostless XCTest |

Open on iOS: whether Frida's attach-mode agent appears in the dyld image list or fires the callback (custom loader?) is **unverified** and needs a jailbroken device.

## 6. Risk register

| Risk area | Risk | Mitigation |
|---|---|---|
| Detection evasion | Attached Frida can hook `/proc` reads, `sysctl`, `dladdr`, or the monitor itself; renamed agents/ports evade name matching | Documented as a race; README guidance: report to backend, treat missing heartbeats as suspicious, tighten interval on sensitive screens |
| False positives | memfd/JIT and WebView executable mappings; Xcode/`debugserver` sets `P_TRACED`; legit SDK swizzling | memfd check gated on Phase 0 baseline; no swizzle/symbol-hook checks in 0.4.0; `techniques` lets consumers weight evidence |
| Performance / battery | Interval scans of maps (hundreds of lines), thread lists, dyld images | Runtime tier only on interval; foreground only; ≥5 s clamp; Phase 0 per-pass timing on POCO F1 and simulator |
| Platform stability | dyld callback runs under a loader lock; heavy work inside can deadlock | Copy-and-enqueue only; no ObjC/Swift allocation-heavy work, UIKit, or logging inside the callback |
| Lifecycle | Single listener slot per core; shared teardown; adapter detach must cover the new channel | Separate `IntegrityMonitor` object with its own listener; adapter tests for teardown of both channels |
| Privacy (UU PDP) | Findings forwarded to a backend may become personal data when linked to a user | Data minimisation kept: artifact lists capped at 8 × 120 chars, own-process paths only, no device identifiers added; README note for consumers |
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
| Phase 4 adapters + Phase 5 samples | Sonnet | after 1–3 |
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
| iOS `P_TRACED` on device | Xcode attach/detach transitions | physical iPhone |

Still open:
1. Ship the memfd check and the mountinfo heuristic only if the Phase 0 baseline is clean, or always behind a `techniques` label?
2. NDK detectors (D5): schedule a separate research/decision record?

## 11. Implementation notes

_Empty until Phase 0._
