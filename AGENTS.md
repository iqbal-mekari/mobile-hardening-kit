# Repository Guidelines

## Project Overview

`mobile_hardening_kit` is a Flutter plugin that gathers client-side integrity, display, and capture signals on Android and iOS. It reports heuristic observations only; it must not block flows or be treated as a security boundary. Flutter 3.24.0 is pinned in CI; Android minimum SDK is 23 and iOS deployment target is 13.0.

## Architecture & Data Flow

- `lib/mobile_hardening_kit.dart` is the public API. It sends point-in-time requests and protection toggles over the `mobile_hardening_kit` `MethodChannel`, and exposes native state changes from `mobile_hardening_kit/events` as a broadcast stream.
- `lib/src/hardening_signal.dart` defines shared signal types and observation records. Keep map fields (`type`, `observedAt`, `metadata`) aligned across Dart, Kotlin, and Swift; snapshots contain at most one record per signal type, while event streams can repeat types for state transitions.
- Detection and lifecycle logic lives in Flutter-free native cores: `native/android/core` (Kotlin, standalone Gradle library; its sources are also compiled into the Flutter Android module via a `srcDirs` entry in `android/build.gradle`) and `ios/Classes/Core` (Swift; exposed by root `Package.swift` and compiled by the pod). `MobileHardeningKitPlugin` on each platform is only a channel adapter; add or change checks in the core, never in the adapter or Dart. Cores expose `snapshot`, `startObserving`/`stopObserving`, and opt-in screen protection, and emit the same `type`/`observedAt`/`metadata` schema. CocoaPods ignores `..` globs and symlinked dirs, so keep iOS core files inside `ios/`.
- `example/flutter/lib/main.dart` shows the consumer flow: snapshot, subscribe/cancel, and opt-in protection. There is no state-management or dependency-injection framework.
- Checks are best-effort: unsupported checks are omitted, unknown signal types fail decoding with `FormatException`, and findings must not be interpreted as proof of device integrity. iOS cannot expose a signing certificate fingerprint or prevent screenshots; Android presentation-display findings can include virtual displays.

## Key Directories

- `lib/`, `lib/src/` — public Flutter API and shared signal model.
- `android/src/main/kotlin/` — Flutter Android adapter; `android/build.gradle` configures the plugin library. `native/android/` — standalone native Android Gradle project (`:core`, Maven publishing, own wrapper).
- `ios/Classes/` — Flutter iOS adapter; `ios/Classes/Core/` — native Swift core and `PrivacyInfo.xcprivacy`; `ios/mobile_hardening_kit.podspec` — CocoaPods integration; `Package.swift` — SwiftPM product `MobileHardeningKit`.
- `example/flutter/` — Flutter sample app (with its own `android/`, `ios/`, `xposed_probe/`); `example/android/` — native Android sample (Gradle project including `:core` by path); `example/ios/` — native iOS SwiftUI sample consuming the root package via SPM. Keep sample UI dependency-free.
- `test/`, `example/flutter/test/` — Dart package tests and example widget test. `native/android/core/src/test/` — Robolectric tests for the Android core. `android/src/test/` — Robolectric tests for the Flutter Android adapter. `ios/Tests/MobileHardeningKitTests/` — hostless XCTest for the Swift core (SPM test target). `example/flutter/ios/RunnerTests/` — XCTest for the Flutter iOS adapter.
- `tool/` — coverage gate scripts used by CI.
- `.github/workflows/` — pull-request CI and tagged Android release automation.

## Development Commands

Run package commands from the repository root; run Flutter example commands from `example/flutter/`:

```sh
flutter pub get
flutter analyze --fatal-infos
flutter test
(cd example/flutter && flutter pub get && flutter analyze --fatal-infos && flutter test)
(cd example/flutter && flutter run)                 # requires a connected device/simulator
(cd example/flutter && flutter build apk --debug)
(cd example/flutter && flutter build apk --release)
```

Lint, test, and coverage per platform (all run in CI on every pull request):

```sh
# Dart
dart format --output=none --set-exit-if-changed lib test example/flutter/lib example/flutter/test
flutter test --coverage && python3 tool/check_lcov.py coverage/lcov.info 95

# Android native core (Robolectric + Jacoco; Android Lint with warnings as errors)
(cd native/android && ./gradlew :core:lintDebug :core:testDebugUnitTest :core:coverageVerification)
# Android Flutter adapter (run after `flutter build apk --debug` in example/flutter)
(cd example/flutter/android && ./gradlew :mobile_hardening_kit:lintDebug :mobile_hardening_kit:testDebugUnitTest :mobile_hardening_kit:coverageVerification)

# iOS (macOS only)
xcrun swift-format lint --strict --recursive Package.swift ios/Classes ios/Tests example/ios/MobileHardeningKitSample example/flutter/ios/RunnerTests example/flutter/ios/Runner/AppDelegate.swift
xcodebuild test -scheme MobileHardeningKit -destination 'platform=iOS Simulator,name=iPhone 17' -enableCodeCoverage YES -resultBundlePath /tmp/spm.xcresult
python3 tool/check_xccov.py /tmp/spm.xcresult MobileHardeningKit.swift 95
```

On macOS, build the iOS example with `cd example/flutter && flutter build ios --simulator --no-codesign`. Run the Flutter iOS adapter tests from `example/flutter/ios/` with `xcodebuild test -workspace Runner.xcworkspace -scheme Runner -destination 'platform=iOS Simulator,name=iPhone 17' -enableCodeCoverage YES -resultBundlePath /tmp/runner.xcresult`, then `python3 tool/check_xccov.py /tmp/runner.xcresult MobileHardeningKitPlugin.swift 90`. Format Dart with `dart format lib test example/flutter/lib example/flutter/test`; format Swift with `xcrun swift-format format --in-place` on the files listed above. Use Flutter's bundled Dart for formatting so CI and local output agree.

## Code Conventions & Common Patterns

- Follow `analysis_options.yaml` (`flutter_lints`) and `dart format`. Use `snake_case.dart` files, `PascalCase` types, and `lowerCamelCase` members.
- Keep the Dart/native boundary small and explicit. Native snapshots and events use the same map schema; timestamps are UTC and metadata should be bounded and contain no user identifiers.
- Use `Future` for method-channel operations and `Stream<HardeningSignal>` for event changes; cancel `StreamSubscription`s when their owner is disposed. Protection is opt-in and separate from event listening.
- Keep signal detection heuristic and platform-specific. Do not silently turn unsupported checks into clean findings, add enforcement decisions, or claim screenshot blocking on iOS.
- Avoid new package dependencies. Runtime dependencies should remain Flutter SDK-only; `flutter_lints` is a Flutter-maintained development dependency.

## Important Files

- `pubspec.yaml` — package identity, SDK constraints, dependencies, and plugin registration.
- `lib/mobile_hardening_kit.dart`, `lib/src/hardening_signal.dart` — public contract and shared model.
- `android/src/main/kotlin/com/mekari/mobile_hardening_kit/MobileHardeningKitPlugin.kt`, `ios/Classes/MobileHardeningKitPlugin.swift` — native collectors and protection helpers.
- `example/ios/RunnerTests/RunnerTests.swift` — native iOS behavior checks.
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `CHANGELOG.md` — CI gates, tag release, and release notes source. Release tags are bare semver (`X.Y.Z`, e.g. `0.2.0`); the tag must match `pubspec.yaml`, the podspec, and the Android core default version (`native/android/core/build.gradle`), and needs a matching `## [X.Y.Z]` changelog heading. The tag workflow publishes the Android AAR to GitHub Packages and attaches it to the GitHub Release; iOS and Flutter consume tagged sources.

## Runtime/Tooling Preferences

Use Flutter/Dart and Pub; the CI workflow installs Flutter 3.24.0 directly from the official Flutter repository. There is no Node, Bun, or npm; the only scripts are the two small Python coverage gates in `tool/`. iOS builds and XCTest require Xcode/CocoaPods on macOS; Android builds use each project's Gradle wrapper (`native/android`, `example/android`, `example/flutter/android`). The Flutter example depends on the package through `path: ../../`.

Build outputs, `.dart_tool/`, Android local properties/Gradle caches, CocoaPods, and generated Flutter plugin files are ignored; edit their source configuration instead. The root package lockfile is intentionally ignored for a reusable library, while the example's lockfile is retained.

## Testing & QA

- Every platform has lint, tests, and a coverage gate, all enforced on every pull request (`.github/workflows/ci.yml`): Dart (`dart format`, `flutter analyze --fatal-infos`, `flutter test --coverage` >= 95% lines), Android core (Android Lint with `warningsAsErrors`, Kotlin `allWarningsAsErrors`, Robolectric tests, Jacoco >= 95% lines / 80% branches), Android Flutter adapter (same lint and tests; >= 95% lines / 60% branches, the residue is Kotlin null-check intrinsics), iOS core (`swift-format lint --strict`, hostless XCTest, >= 95% lines), iOS Flutter adapter (XCTest in the Runner host, >= 90% lines).
- Android gates fail if no coverage data exists (a missing exec file would otherwise pass silently). Do not lower thresholds to land a change; add tests. New detector logic goes in the core behind the injectable seams (`FileAccess` on Android, `HardeningProbe` on iOS) so both positive and negative paths are testable.
- iOS overlay tests need no app host because the key window and app-active state come from `HardeningProbe`; do not move core tests into a hosted target (Xcode coverage for package targets is unreliable there).
- Do not equate passing tests with 100% line coverage. Before changing a platform collector or channel contract, verify the corresponding native build or simulator/device path as well as Dart tests.
