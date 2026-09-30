# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- Flutter-free native cores for direct Android (`native/android`, Gradle library with Maven publishing) and iOS (root `Package.swift`, product `MobileHardeningKit`) integration, with `snapshot`, `startObserving`/`stopObserving`, and opt-in screen protection.

- Native samples next to the Flutter example: Android (`example/android`) and iOS SwiftUI app (`example/ios`, SPM local package). The Flutter example moved to `example/flutter`.
- Android unit tests (Robolectric) for the native core and the Flutter adapter, iOS XCTest suite for the Swift package, and expanded Dart channel tests; all reach at least 90% line coverage.
- CI runs lint, tests, and coverage gates for Dart, Android (core and Flutter adapter), and iOS (core and Flutter adapter) on every pull request (`tool/check_lcov.py`, `tool/check_xccov.py`, Gradle `coverageVerification`).

### Fixed
- Android: declare `android.permission.DETECT_SCREEN_CAPTURE`. Without it, starting event observation on Android 14+ threw `SecurityException` from `registerScreenCaptureCallback` and crashed the host app (Flutter and native).

### Changed
- Android signature check now requires every reported signer to match the expected fingerprint (previously only the first signer was compared), closing an extra-forged-signer bypass flagged by Android Lint. Multi-signer apps report a mismatch against a single fingerprint.
- Android and Kotlin warnings are errors; Android Lint runs with `warningsAsErrors`.
- The Flutter plugins are now thin adapters over the native cores; the method/event channel contract and Dart API are unchanged.
- The iOS `PrivacyInfo.xcprivacy` moved to `ios/Classes/Core` and is now bundled by the pod (`resource_bundles`) and the Swift package.

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
