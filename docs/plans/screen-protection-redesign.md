**Classification: INTERNAL**

# Screen protection redesign (0.3.0, breaking)

Branch: `feat/screen-protection-redesign` · Target release: `0.3.0` · Status: plan, not started

## 1. Goal

Replace the boolean `setScreenProtectionEnabled` with an explicit, per-capability protection API that behaves the same way on Android and iOS and **reports what the platform actually applied**. Add iOS capture blanking as a clearly labelled best-effort option, add Android 15 recording detection, and move iOS capture detection to the scene-level API.

## 2. Decisions (agreed 2026-10-28)

| # | Decision | Rationale |
|---|---|---|
| D1 | Breaking redesign; remove `setScreenProtectionEnabled` | The bool means different things per platform (Android `FLAG_SECURE` vs iOS app-switcher blur). Any shorthand mapping either keeps that inconsistency or silently changes iOS behaviour. Pre-1.0, consumers are our own samples. |
| D2 | iOS gets two separate opt-ins: supported reactive cover **and** best-effort secure-field blanking (off by default) | Apple provides no prevention API; the secure-field technique is undocumented and fragile, so it must never be implied by another flag. |
| D3 | Ship Android 15 recording callback, iOS `sceneCaptureState`, Android per-window guidance in the same release | Closes known detection gaps found in research. |
| D4 | No third-party dependency (ScreenProtectorKit, no_screenshot) | Closed binary / duplicated scope; kit stays in-house and dependency-light. no_screenshot (BSD-style) is a **reference only** for iOS edge cases; no code is copied. |

## 3. Non-goals

- Per-view protection (Flutter renders into a single view; native per-view API may follow later).
- Defeating external cameras, rooted/jailbroken hooks (LSPosed/Frida stripping `FLAG_SECURE`), or capture cards. Documented as out of scope.
- Any enforcement decision. The kit still reports and applies opt-in window protection only; it never blocks a flow.

## 4. Public API

### 4.1 Dart (`lib/mobile_hardening_kit.dart`, new `lib/src/screen_protection.dart`)

```dart
class ScreenProtection {
  const ScreenProtection({
    this.blockCapture = false,
    this.obscureWhileCaptured = false,
    this.obscureAppSwitcher = false,
  });
  static const off = ScreenProtection();
  final bool blockCapture;
  final bool obscureWhileCaptured;
  final bool obscureAppSwitcher;
}

class ScreenProtectionState {
  final bool captureBlocked;
  final bool obscuresWhileCaptured;
  final bool obscuresAppSwitcher;
  /// `<option>:<reason>` entries for requested options the platform could not apply.
  final List<String> unavailable;
}

Future<ScreenProtectionState> setScreenProtection(ScreenProtection protection);
```

Kotlin and Swift mirror these names: `ScreenProtection` data class/struct, `ScreenProtectionState`, `setScreenProtection(_:)` returning the state synchronously (main thread).

### 4.2 Channel contract

- Method `setScreenProtection`, args `{blockCapture, obscureWhileCaptured, obscureAppSwitcher}` (bools), returns `{captureBlocked, obscuresWhileCaptured, obscuresAppSwitcher, unavailable: [String]}`.
- Method `setScreenProtectionEnabled` is removed from both adapters (unknown method → `notImplemented`).
- Event schema unchanged (`type` / `observedAt` / `metadata`). `screenCaptureActive` events now also come from Android 15+ and carry `metadata.source`.

### 4.3 Unavailability reasons (closed set, documented in README)

`blockCapture:iosAppOnMac`, `blockCapture:windowNotReady`, `blockCapture:secureLayerUnavailable`, `obscureWhileCaptured:apiLevel`, `obscureAppSwitcher:apiLevel`, `*:noActivity` / `*:noWindow`.

## 5. Platform mapping

| Option | Android | iOS |
|---|---|---|
| `blockCapture` | `FLAG_SECURE` on the attached activity window (existing logic; original flag restored on detach). Blanks screenshots, recordings, casting, Recents. | **Best-effort, unsupported by Apple.** Reparent `window.layer` under the secure-text-entry sublayer of an off-screen `UITextField`, toggle `isSecureTextEntry`. Skipped on `isiOSAppOnMac`. Restores the original layer tree on disable/teardown. |
| `obscureWhileCaptured` | API 35+: `WindowManager.addScreenRecordingCallback`; add `FLAG_SECURE` while state is `SCREEN_RECORDING_STATE_VISIBLE`, restore after. Below 35: `unavailable` (`apiLevel`), unless `blockCapture` already covers it. | Cover the key window with an opaque view while capture is active. iOS 17+: scene capture state trait; iOS 13–16: `UIScreen.capturedDidChangeNotification` + `isCaptured`. Reactive: first frames may leak. |
| `obscureAppSwitcher` | API 33+: `Activity.setRecentsScreenshotEnabled(false)`. Below 33: `unavailable` unless `blockCapture` is on (`FLAG_SECURE` already hides Recents). | Existing blur on `willResignActive`, removed on `didBecomeActive`. |

Detection additions:
- **Android:** declare `android.permission.DETECT_SCREEN_RECORDING` in `native/android/core/src/main/AndroidManifest.xml`; emit `screenCaptureActive` `{active, source: "screenRecordingCallback"}` on state change while observing. Keep the API 34 `ScreenCaptureCallback` as `screenshotTaken` only (do not mislabel it as recording).
- **iOS:** replace `UIScreen.main.isCaptured` in `SystemProbe` with scene-level capture state on iOS 17+, fallback below; emit `screenCaptureActive` `{active, source: "sceneCaptureState" | "screenIsCaptured"}`. Resolve the key window via connected `UIWindowScene`s instead of deprecated `UIApplication.shared.windows`.

## 6. Risk register

| Risk area | Risk | Mitigation |
|---|---|---|
| Platform stability | iOS secure-field technique depends on undocumented sublayer order (`first` < iOS 17, `last` ≥ 17) and has known crash/layout issues (iOS 26 circular hierarchy, RTL shift, Mac host blanking) | Off by default; validate the target sublayer exists before reparenting else report `secureLayerUnavailable`; add/remove field from window before reparenting; force LTR; per-iOS-release device matrix gate before each release |
| App Review | Use of undocumented UIKit behaviour (no private API symbols). ASSUMPTION: low rejection risk, no documented rejections found | Product owner risk acceptance recorded in PR; README states "not supported by Apple" |
| Data exposure | Reactive cover leaks initial frames; Android 15 callback misses scrcpy / `screenrecord` / pre-existing recordings; `FLAG_SECURE` is per window (dialogs, popups, separate native windows) | Document limits; recommend `blockCapture` for sensitive flows; Android dialog guidance |
| Device trust | Root/LSPosed/Frida strip `FLAG_SECURE`; jailbreak tweaks | Out of scope; consumers correlate with `root` / `instrumentation` signals |
| Build/toolchain | `addScreenRecordingCallback` needs `compileSdk = 35`; compatibility with pinned Flutter 3.24.0 / its AGP and Robolectric SDK 35 support is **unverified** | Phase 0 spike; bump `compileSdk` in `native/android/core/build.gradle` and `android/build.gradle` |
| Lifecycle | Flutter 3.24 iOS uses app-delegate lifecycle; UIScene apps may not deliver callbacks | Attach lazily on first `setScreenProtection` call; reattach on scene/window activation |

## 7. Phases

### Phase 0 — Spikes and verification (gate for Phase 2/3)

1. **Android toolchain:** bump `compileSdk` to 35 in both Gradle modules; confirm `:core:lintDebug :core:testDebugUnitTest` and `example/flutter` debug build pass on Flutter 3.24.0. Confirm Robolectric runs `@Config(sdk = [35])`.
2. **Android behaviour (ARTEMIS on a physical Android 15+ device; reconnect the ARTEMIS MCP first):**
   - `FLAG_SECURE` blanks Flutter `showDialog`, bottom sheets, and `PopupMenu` (same window?) vs platform views and native dialogs.
   - `addScreenRecordingCallback` fires for the system recorder; record that scrcpy and `adb shell screenrecord` do not trigger it.
   - Adding `FLAG_SECURE` mid-recording blanks subsequent frames.
3. **iOS behaviour (manual on physical devices; ARTEMIS is Android-only):** secure-field blanking for screenshot, Control Center recording, AirPlay mirroring, QuickTime-over-USB, on iOS 16, 17, 18, and 26; measure reactive-cover latency; confirm the exact iOS 17+ scene capture state trait API name and registration call against Apple docs (currently unverified).

Exit: a short findings note appended to this plan; any failing assumption changes §5 before implementation.

### Phase 1 — Shared contract

- Dart: `ScreenProtection`, `ScreenProtectionState` (with `fromMap`, strict decoding: unknown keys ignored, missing keys → `FormatException`), `setScreenProtection`; remove `setScreenProtectionEnabled`. Export from `lib/mobile_hardening_kit.dart`.
- Tests: `test/mobile_hardening_kit_test.dart` channel round-trip, decoding errors, `off` constant. Gate: ≥95% lines.

### Phase 2 — Android core (`native/android/core`)

- `ScreenProtection` / `ScreenProtectionState` in `HardeningSignal.kt` (or a new `ScreenProtection.kt`).
- `MobileHardeningKit.setScreenProtection(...)`: compute effective `FLAG_SECURE` = `blockCapture || originalSecureFlag || (obscureWhileCaptured && recordingVisible)`; `setRecentsScreenshotEnabled` on API 33+; restore all on `detachActivity()`.
- Recording callback register/unregister alongside the existing screenshot callback; needed both when observing (signal) and when `obscureWhileCaptured` is on (protection), with one shared registration.
- Manifest: `DETECT_SCREEN_RECORDING`.
- Robolectric tests for every option × API level (23, 32, 33, 34, 35), original-flag restore, callback lifecycle. Gates: ≥95% lines / ≥80% branches.

### Phase 3 — iOS core (`ios/Classes/Core`)

- `ScreenProtection` / `ScreenProtectionState` structs.
- New injectable seam `SecureCaptureContainer` (protocol) wrapping the `UITextField` reparenting, so hostless XCTest can cover attach/detach/failure paths; `SystemSecureCaptureContainer` holds the UIKit implementation.
- Extend `HardeningProbe`: `isiOSAppOnMac`, scene-level `isScreenCaptured`, scene-based `keyWindow()`.
- Capture cover: opaque view tagged with a new public `captureCoverViewIdentifier`; driven by capture-state changes.
- Tests in `ios/Tests/MobileHardeningKitTests` for each option, unavailability reasons, teardown restoring the layer tree. Gate: ≥95% lines; `swift-format lint --strict`.

### Phase 4 — Adapters

- `android/.../MobileHardeningKitPlugin.kt`, `ios/Classes/MobileHardeningKitPlugin.swift`: map `setScreenProtection` args/results; remove old method.
- Adapter tests: `android/src/test/...` (≥95% lines / ≥60% branches), `example/flutter/ios/RunnerTests/RunnerTests.swift` (≥90% lines).

### Phase 5 — Samples, docs, policy

- Update `example/flutter/lib/main.dart` (three toggles + state display), `example/flutter/test/widget_test.dart`, `example/android/.../MainActivity.kt`, `example/ios/.../HardeningModel.swift`. Native samples consume released artifacts, so they move to 0.3.0 **after** tagging (follow-up PR, per AGENTS.md).
- README: new API, platform mapping table (§5), unavailability reasons, limits, Android per-window guidance (dialogs/popups/platform views/`SurfaceView.setSecure`), migration table from 0.2.x.
- AGENTS.md: replace "do not … claim screenshot blocking on iOS" with "iOS capture blanking is opt-in, best-effort, unsupported by Apple; never describe it as guaranteed."
- CHANGELOG `## [Unreleased]`: **Changed (breaking)**, **Added**, migration notes.

### Phase 6 — Release 0.3.0

- Bump `pubspec.yaml`, `ios/mobile_hardening_kit.podspec`, `native/android/core/build.gradle` default version; `## [0.3.0]` heading.
- Re-run Phase 0 device matrix on the release candidate. Tag `0.3.0` only after user approval.

## 8. Migration (0.2.x → 0.3.0)

| 0.2.x | 0.3.0 equivalent |
|---|---|
| `setScreenProtectionEnabled(true)` on Android | `setScreenProtection(ScreenProtection(blockCapture: true))` |
| `setScreenProtectionEnabled(true)` on iOS | `setScreenProtection(ScreenProtection(obscureAppSwitcher: true))` |
| `setScreenProtectionEnabled(false)` | `setScreenProtection(ScreenProtection.off)` |
| Recommended for sensitive flows | `ScreenProtection(blockCapture: true, obscureWhileCaptured: true, obscureAppSwitcher: true)` and check `state.unavailable` |

## 9. Execution and delegation

| Work | Model tier | Mode |
|---|---|---|
| Phase 0 toolchain spike | Sonnet | background subagent |
| Phase 0 Android device exploration | ARTEMIS (Pro) driven by orchestrator | needs ARTEMIS reconnected + device choice |
| Phase 1 Dart contract | Sonnet | parallel with Phase 2/3 after Phase 0 |
| Phase 2 Android core | Sonnet | parallel |
| Phase 3 iOS core (secure container) | Opus | parallel; security-sensitive and fragile |
| Phase 4 adapters + Phase 5 samples | Sonnet | after 1–3 |
| README/CHANGELOG/AGENTS.md edits | Haiku draft, orchestrator review | after 4 |
| Final cross-platform review | Opus | before PR |

## 10. Open questions

1. Who signs the risk acceptance for the iOS secure-field technique (product owner / security)?
2. Minimum device matrix for the release gate (which physical Android 15/16 and iOS 16–26 devices are available)?
3. Should `obscureWhileCaptured` on iOS use a blur or an opaque/branded cover (opaque leaks less)?
