# Repository Guidelines

## Project Overview

`mobile_hardening_kit` is a Flutter plugin that gathers client-side integrity, display, and capture signals on Android and iOS. It reports heuristic observations only; it must not block flows or be treated as a security boundary. Flutter 3.24.0 is pinned in CI; Android minimum SDK is 23 and iOS deployment target is 13.0.

## Architecture & Data Flow

- `lib/mobile_hardening_kit.dart` is the public API. It sends point-in-time requests and protection toggles over the `mobile_hardening_kit` `MethodChannel`, and exposes native state changes from `mobile_hardening_kit/events` as a broadcast stream.
- `lib/src/hardening_signal.dart` defines shared signal types and observation records. Keep map fields (`type`, `observedAt`, `metadata`) aligned across Dart, Kotlin, and Swift; snapshots contain at most one record per signal type, while event streams can repeat types for state transitions.
- Android's `ActivityAware` plugin performs platform checks and manages activity/window and display lifecycles. iOS registers a Flutter plugin and uses UIKit notifications for capture, display, and app-state observations. Platform-specific checks belong in their native implementations; do not duplicate them in Dart.
- `example/lib/main.dart` shows the consumer flow: snapshot, subscribe/cancel, and opt-in protection. There is no state-management or dependency-injection framework.
- Checks are best-effort: unsupported checks are omitted, unknown signal types fail decoding with `FormatException`, and findings must not be interpreted as proof of device integrity. iOS cannot expose a signing certificate fingerprint or prevent screenshots; Android presentation-display findings can include virtual displays.

## Key Directories

- `lib/`, `lib/src/` — public Flutter API and shared signal model.
- `android/src/main/kotlin/` — Android native plugin implementation; `android/build.gradle` configures the library.
- `ios/Classes/`, `ios/mobile_hardening_kit.podspec` — Swift implementation and CocoaPods integration.
- `example/lib/`, `example/android/`, `example/ios/` — runnable host app and platform projects.
- `test/`, `example/test/`, `example/ios/RunnerTests/` — Dart package tests, example widget test, and iOS simulator XCTest.
- `.github/workflows/` — pull-request CI and tagged Android release automation.

## Development Commands

Run package commands from the repository root; run example commands from `example/`:

```sh
flutter pub get
flutter analyze --fatal-infos
flutter test
(cd example && flutter pub get && flutter analyze --fatal-infos && flutter test)
(cd example && flutter run)                         # requires a connected device/simulator
(cd example && flutter build apk --debug)
(cd example && flutter build apk --release)
```

On macOS, build the iOS example with `cd example && flutter build ios --simulator --no-codesign`. Run native iOS tests from `example/ios/` with `xcodebuild test -workspace Runner.xcworkspace -scheme Runner -destination 'platform=iOS Simulator,name=iPhone 17'`. Format Dart with `dart format lib test example/lib example/test`; format Swift with `xcrun swift-format format --in-place ios/Classes/MobileHardeningKitPlugin.swift example/ios/RunnerTests/RunnerTests.swift`.

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
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `CHANGELOG.md` — CI gates, tag release, and release notes source. Release tags use `v*` and require a matching changelog heading.

## Runtime/Tooling Preferences

Use Flutter/Dart and Pub; the CI workflow installs Flutter 3.24.0 directly from the official Flutter repository. There is no Node, Bun, npm, or custom script runner. iOS builds and XCTest require Xcode/CocoaPods on macOS; Android builds use the example Gradle wrapper. The example app depends on the package through `path: ../`.

Build outputs, `.dart_tool/`, Android local properties/Gradle caches, CocoaPods, and generated Flutter plugin files are ignored; edit their source configuration instead. The root package lockfile is intentionally ignored for a reusable library, while the example's lockfile is retained.

## Testing & QA

- Run `flutter test` for the package and `cd example && flutter test` for the example. Package tests cover native-map decoding boundaries, safe defaults, and signal equality/hash behavior; the example test checks its consumer-facing surface.
- Use `flutter analyze --fatal-infos` for both package and example. CI runs these analyses, both Dart test suites, and an Android debug APK build on pull requests.
- `example/ios/RunnerTests/` contains XCTest coverage for simulator findings and protection behavior without an event subscription. Android behavior is verified by compiling/running the example; no separate Android unit-test suite or coverage threshold is configured.
- Do not equate passing tests with 100% line coverage. Before changing a platform collector or channel contract, verify the corresponding native build or simulator/device path as well as Dart tests.
