# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Changed (breaking)
- The iOS minimum deployment target is now 15.0 (was 13.0), the minimum of the Xcode 27 iPhoneOS SDK. This applies to the CocoaPods podspec and the SwiftPM package.
- `setScreenProtectionEnabled` is removed from the Dart API, both native cores, and both Flutter adapters (the channel answers `notImplemented`). Use `setScreenProtection(ScreenProtection(...))`, which takes independent `blockCapture`, `obscureWhileCaptured`, and `obscureAppSwitcher` options and returns a `ScreenProtectionState`. See the README's "Migrating from 0.2.x" table: Android `true` becomes `blockCapture: true`, iOS `true` becomes `obscureAppSwitcher: true`, `false` becomes `ScreenProtection.off`.
- Toolchain floors follow the Flutter 3.47.8 baseline: Flutter 3.47.8 and Dart 3.13.7 (`flutter: '>=3.47.8'`, `sdk: '>=3.13.7 <4.0.0'`), Android min SDK 24 (was 23), Android Gradle Plugin 9.0.1, Gradle 9.1.0, Kotlin Gradle plugin 2.3.20, JDK 17 (Java/JVM target 17, was 1.8), and `compileSdk` 36. The AAR declares `minCompileSdk` 36, so consumers must compile against SDK 36 or later. The Android library and Flutter plugin use AGP 9 built-in Kotlin; Flutter apps can keep `android.builtInKotlin=false`.
- The library manifest now also merges `android.permission.DETECT_SCREEN_RECORDING` (normal permission) into consuming apps.

### Added
- `setScreenProtection` reports what the platform actually applied: `captureBlocked`, `obscuresWhileCaptured`, `obscuresAppSwitcher`, and an `unavailable` list of `<option>:<reason>` entries for requested options it could not apply.
- Android 13+ app-switcher opt-out through `Activity.setRecentsScreenshotEnabled(false)`, used by `obscureAppSwitcher`.
- Android 15+ screen-recording state: `screenCaptureActive` events with `metadata.source` `screenRecordingCallback`, and `obscureWhileCaptured` adds `FLAG_SECURE` only while a recording is visible. The callback can miss scrcpy, `adb shell screenrecord`, and recordings that started before observation.
- iOS capture state from the window-scene trait on iOS 17+ (`metadata.source` `sceneCaptureState`), falling back to `UIScreen.isCaptured` (`screenIsCaptured`) on iOS 15–16.
- iOS opt-in `blockCapture`: best-effort capture blanking through a secure text field layer. It relies on undocumented UIKit behaviour, is not supported by Apple, and may break in any iOS release.
- iOS opaque capture cover (identifier `mobile_hardening_kit_capture_cover_view`) shown while the screen is captured, used by `obscureWhileCaptured`. It is reactive; the first frames of a capture can leak.
- CI enforces 95% line coverage on the new iOS core files `ScreenProtection.swift` and `SecureCaptureContainer.swift` as well as `MobileHardeningKit.swift`.
- README documentation of the per-platform protection mapping, `unavailable` reasons, per-window `FLAG_SECURE` limits, and migration from 0.2.x.
- The Flutter sample demonstrates local kit findings alongside independently server-verified Google Play Integrity verdicts, with sample-owned OR, AND, and source-precedence decision policies. The Play SDK dependency is confined to the sample Android app; the kit API and dependencies are unchanged.
- A Go sample verification backend validates Play tokens, request binding, package identity, and freshness using server-only Application Default Credentials. Its behavior tests run in CI; setup and trust limitations are documented in the sample READMEs.
- Runtime integrity monitor: `integrityEvents(IntegrityMonitorConfig)` in Dart and `startMonitoring` / `stopMonitoring` in the Kotlin and Swift cores. It is opt-in, report-only, and foreground only; it re-checks on a schedule matched to when each tool can attach and reports only `detected`, `changed`, or `cleared` findings.
- `checkIntegrityNow()` runs one monitor pass now (`trigger: manual`) in Dart, Kotlin, and Swift.
- `screenEvents`, the screen-event stream (screenshot, capture, external display), on its own EventChannel, separate from integrity findings.
- Integrity event metadata: `change`, `trigger`, and `techniques`, where `techniques` names the evidence source behind each finding.
- Android detectors: thread names (`threadName`), `TracerPid` (`tracerPid`), executable private memfd mappings (`memfdExec`), anonymous RWX as supporting evidence only (`anonRwx`), libart text-segment split (`artSegments`, low confidence), Magisk/Zygisk mount markers (`mountinfo`), and the Frida listener port probe on API 28 and below (`port`).
- iOS dyld image-load observer, registered once per process, emitting `trigger: imageLoad`, with `dyldImage`, `dyldImageLoad`, and `pTraced` evidence.
- README sections for the integrity monitor (usage, timing table, `techniques` vocabulary, limits, untested coverage, data handling) and migration from 0.3.x.

### Changed
- The Flutter example adopts the UIScene lifecycle, which Xcode 27 builds require, and no longer needs the Podfile deployment-target override (the Flutter 3.47.8 engine pod declares iOS 15.0). Flutter is pinned per project with fvm (`.fvmrc`).
- The native Android sample (`example/android`) now consumes the released 0.2.0 AAR from the GitHub Release assets (anonymous, via the attached Gradle module metadata), and the native iOS sample (`example/ios`) consumes the tagged 0.2.0 sources through a remote SPM reference, instead of building the library from the working tree.
- Instrumentation, debugger, and root/jailbreak metadata gains `techniques`, plus new keys: `anonRwxCount` and `artTextSegments` (Android instrumentation, whose `artifacts` may now include `thread:<name>` entries), `tracerPid` (Android debugger), and `mountMarkers` (Android root).
- Instrumentation name matching uses the file name only (last path component), case-insensitively, against specific tokens. Android: `frida-agent`, `frida-gadget`, `libfrida`, `libxposed`, `xposedbridge`, `lsposed`, `libsubstrate`, `libhooker`. iOS: `fridagadget`, `frida-gadget`, `frida-agent`, `libfrida`, `mobilesubstrate`, `cydiasubstrate`, `libsubstitute`, `substitute-loader`, `ellekit`, `libhooker`. Bare `frida`, `substrate`, `gadget`, and `xposed` no longer match, so a library named `frida.so` or `xposed.jar` is not reported, and app paths containing words such as "Friday" no longer cause false positives.
- Instrumentation `artifacts` contain file names only, never directory paths, on both platforms, at most 8 entries of at most 120 characters. Android memfd entries read like `memfd:frida-agent-64.so`, and thread entries are `thread:<name>`. Root and jailbreak `artifacts` remain fixed system paths from the kit's own lists.
- The integrity monitor interval is clamped to [5 s, 24 h] in Dart, Android, and iOS.
- Android: `snapshot()` through the Flutter plugin runs off the platform thread, so it no longer reads `/proc` on the main thread.
- Android: the integrity monitor starts paused when no activity is attached. The start pass still runs, and the interval begins when an activity is attached or started.
- Dart: each `integrityEvents()` call returns a stream bound to its own configuration and native session. Listening to it while a different session is active fails that subscription with a `StateError`, in addition to the `StateError` thrown at call time when a different session is already active.
- The Android Frida listener port probe (`/proc/net/tcp`) runs only on API 28 and below. It is passive: there is no active `connect()` probe and no `INTERNET` permission.
- Java-side Xposed `Class.forName` probes are removed. Phase 0 showed they do not reveal LSPosed, so the kit makes no LSPosed detection claim.
- iOS `screenshotTaken` metadata gains `source: userDidTakeScreenshotNotification`; `active` is kept for compatibility.
- iOS `observedAt` includes milliseconds, matching Android.

### Deprecated
- `MobileHardeningKit.stream` is deprecated in favour of `screenEvents`. It is removed in 0.5.0.

### Fixed
- Dart: a second listener on `stream` re-subscribed the native channel, and cancelling either listener stopped both. All listeners on all kit instances now share one native subscription for `screenEvents` and one for `integrityEvents`.
- Android: an integrity monitor interval of `Long.MAX_VALUE` caused a busy loop. The interval is now clamped to [5 s, 24 h].
- Android: the integrity monitor leaked the attached activity when it was destroyed without `detachActivity()`. Destroying the attached activity now pauses the monitor and unbinds it.
- iOS: image loads that raced dyld callback registration were mislabelled as replayed. A load is now live unless its image was already loaded when observation began.

### Security
- Gradle wrapper properties pin `distributionSha256Sum` for the Gradle distribution in the native Android core and both Android samples. CI and the release workflow run `gradle/actions/wrapper-validation` to check wrapper checksums.

## [0.2.0] - 2026-09-30

### Added
- Flutter-free native cores for direct integration: Android (`native/android/core`, Gradle library) and iOS (root `Package.swift`, SwiftPM product `MobileHardeningKit`, iOS 13+). Both provide `snapshot`, `startObserving`/`stopObserving`, and opt-in screen protection with the same `type`/`observedAt`/`metadata` signal schema.
- Tagged releases now build the Android AAR and publish it to this repository's GitHub Packages (`com.mekari.mobile_hardening_kit:mobile-hardening-kit`), and attach the AAR, POM, Gradle module metadata, and sources jar to the GitHub Release. iOS and Flutter consumers use the tagged sources directly.
- Native samples next to the Flutter example: Android (`example/android`) and iOS SwiftUI app (`example/ios`, SPM local package). The Flutter example moved to `example/flutter`.
- Android unit tests (Robolectric) for the native core and the Flutter adapter, an iOS XCTest suite for the Swift package, and expanded Dart channel tests, each at or above 95% line coverage.
- CI runs lint, tests, and coverage gates for Dart, Android (core and Flutter adapter), and iOS (core and Flutter adapter) on every pull request (`tool/check_lcov.py`, `tool/check_xccov.py`, Gradle `coverageVerification`).

### Fixed
- Android: declare `android.permission.DETECT_SCREEN_CAPTURE`. Without it, starting event observation on Android 14+ threw `SecurityException` from `registerScreenCaptureCallback` and crashed the host app (Flutter and native).
- Android: the signature check now requires every reported signer to match the expected fingerprint. Previously only the first signer was compared on API < 28, so an extra forged signer could pass (flagged by Android Lint `PackageManagerGetSignatures`). Multi-signer apps report a mismatch against a single fingerprint.

### Changed
- The Flutter plugins are now thin adapters over the native cores; the method/event channel contract and Dart API are unchanged.
- Android and Kotlin warnings are errors; Android Lint runs with `warningsAsErrors`.
- The iOS `PrivacyInfo.xcprivacy` moved to `ios/Classes/Core` and is now bundled by the pod (`resource_bundles`) and the Swift package.
- Release tags are bare semantic versions (`0.2.0`), matching the existing `0.1.0` tag, SwiftPM, and pub git refs. The release workflow triggers on any `X.Y.Z` tag, requires the tag to match `pubspec.yaml`, the podspec, and the Android core default version, and uses only that version's changelog section as the release notes.
- Example paths: `example/` is now `example/flutter`.

## [0.1.0] - 2026-09-25

### Added
- Shared Flutter API for point-in-time integrity signal snapshots and native display/capture transition events.
- Android root, instrumentation, debugger, optional signer-fingerprint, emulator, accessibility, developer-mode, screenshot (Android 14+), and external-display collectors.
- iOS jailbreak, instrumentation, debugger, simulator, code-signature-presence, capture, screenshot, and external-display collectors.
- Opt-in Android `FLAG_SECURE` and iOS app-switcher snapshot obscuring.
- Example app, Dart tests, pull-request checks, tagged release APK artifact, and changelog-backed GitHub Release notes.
- Standalone Android Xposed/LSPosed no-hook probe scoped to the example app for authorized instrumentation testing.

### Changed
- Breaking API change: `snapshot()` returns an ordered `List<HardeningSignal>` with at most one record per type; confidence is removed from snapshot and event records so consuming apps own policy decisions.
- The example displays raw snapshot arrays and stream-event records without confidence or policy labels.
- Android root detection recognizes the visible Magisk manager package without invoking `su`; refreshed POCO and Android 17/API 37 emulator captures document the observed root, Frida-backed instrumentation, and emulator findings.

### Limitations
- Signals are heuristic, may miss tampering, and must not be treated as an enforcement boundary.
- iOS apps cannot read a signing-certificate fingerprint from the sandbox; the kit only checks for the executable's code-signature load command.
- iOS does not expose screenshot prevention; its helper only obscures the app-switcher snapshot.
- Android cannot reliably enumerate screen-recording apps; screenshot event callbacks require Android 14+.
