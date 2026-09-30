# Changelog

All notable changes to this project are documented here.

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
