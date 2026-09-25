# Mobile Hardening Kit

A dependency-light Flutter plugin that collects heuristic client-side integrity and display signals through in-house Dart, Kotlin, and Swift implementations. **The kit reports signals; it never blocks a user flow or makes a product risk decision.** Client-side checks are bypassable and are not a security boundary.

## Requirements

- Flutter 3.24.0 or later
- Android min SDK 23
- iOS deployment target 13.0
- No third-party Dart runtime dependencies. The only package development dependency besides Flutter SDK test tools is the Flutter-maintained `flutter_lints` analyzer rules package.

## Add the package

```yaml
dependencies:
  mobile_hardening_kit:
    git:
      url: git@github.com:iqbal-mekari/mobile-hardening-kit.git
      ref: v0.1.0
```

## Collect signals

```dart
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

final hardening = MobileHardeningKit(
  // Optional. SHA-256 hex fingerprint of the expected Android signing cert.
  expectedSigningCertificateSha256: '0123...abcd',
  // Android enabled accessibility services not listed here are reported as
  // low-confidence ACCESSIBILITY_UNRECOGNIZED findings.
  trustedAccessibilityPackages: const {'com.example.approvedaccessibility'},
);

final findings = await hardening.snapshot();
for (final finding in findings) {
  // Forward to app-owned risk handling; don't assume a clean scan is proof.
  print('${finding.type}: ${finding.confidence} ${finding.metadata}');
}

final subscription = hardening.stream.listen((finding) {
  // Receives platform-observable display/capture state changes, not a poll.
});
// Cancel when the owning screen/service is disposed.
await subscription.cancel();
```

Set `expectedSigningCertificateSha256` to the signing certificate's SHA-256 digest as hexadecimal, with or without colons; an unset fingerprint disables this check. iOS does not expose the app signing-certificate fingerprint to a sandboxed process, so iOS reports an absent Mach-O code-signature load command, not a pinned certificate mismatch. Plan certificate verification and authoritative integrity decisions on the server.

`HardeningSignal.metadata` is bounded, platform-generated, and intended to contain no user identifiers. `observedAt` is UTC. Unsupported or unavailable checks are omitted rather than reported as clean.

## Capabilities and platform constraints

| Signal | Android | iOS |
| --- | --- | --- |
| Root / jailbreak | `su`, Magisk/KernelSU paths, test-key build tags | Common jailbreak files and URL schemes; scheme detection requires the app's `LSApplicationQueriesSchemes` allowlist |
| Instrumentation | Frida/Xposed/LSPosed/Substrate mappings and Frida TCP listener ports | Loaded-image names for Frida/Substrate/Substitute/ElleKit/Xposed indicators |
| Debugger | Runtime debugger attachment | `sysctl` traced-process flag |
| Signature integrity | SHA-256 of installed signing certificate compared with caller-supplied fingerprint | Detects absence of Mach-O code-signature command only; cannot expose/compare signing certificate fingerprint |
| Emulator / simulator | Multiple build-property heuristics | Simulator build environment |
| Accessibility / developer settings | Reports enabled external accessibility packages not caller-trusted, developer options, or ADB; low confidence | Not exposed by the platform APIs used here |
| Capture / display | Android 14+ screenshot callback while the signal stream is listened to; secondary presentation displays (virtual displays included) | Screen recording/mirroring state, screenshot event, and external display connection events |
| Protection helper | `FLAG_SECURE` on attached Flutter window | Blurred app-switcher snapshot while app is backgrounded; does not prevent screenshots or screen recording |

Detection limitations and false positives are expected. A rooted device may hide artefacts; legitimate development builds, emulators (including their virtual presentation displays), accessibility services, screen sharing, and external displays can produce signals. Android screenshot event detection requires API 34+; screen protection via `FLAG_SECURE` works from min SDK 23. Generic Android screen-recording app detection is not available to ordinary apps and is not claimed.

## Opt-in display protection

Protection is disabled by default. Enable it only around product-selected sensitive flows, then restore it when leaving that flow:

```dart
await hardening.setScreenProtectionEnabled(true);
try {
  await showSensitiveFlow();
} finally {
  await hardening.setScreenProtectionEnabled(false);
}
```

Android applies `FLAG_SECURE` to the attached Flutter activity window (so it affects that whole window). iOS adds a blur overlay only during app-switcher snapshot capture. iOS does not provide a supported API to block user screenshots; the helper only obscures the background snapshot.

## Example

`example/` is a Flutter app that runs a scan, displays current findings, subscribes to display/capture events, and toggles the opt-in protection helper. Run it on an Android or iOS device/simulator with `cd example && flutter run`.

## Testing signal triggers

From the repository root, start the example on a device or simulator:

```sh
cd example
flutter pub get
flutter devices
flutter run -d DEVICE_ID
```

The example takes a snapshot on launch and subscribes to the event stream. After changing a device setting, tap **Scan now** to refresh snapshot findings. Screenshot and display changes arrive through the stream; keep the app open and leave the protection switch off while testing screenshot events. A signal may be absent when a platform or device cannot expose that check.

### Android

Use an API 34+ emulator or device for screenshot-event testing.

| Signal | Trigger |
| --- | --- |
| `emulator` | Run on an Android emulator and tap **Scan now**. Emulator heuristics vary by system image. |
| `devModeEnabled` | Enable **Developer options** or **USB debugging** in Android Settings, return to the app, and scan. |
| `debuggerAttach` | Attach an Android Studio **native** debugger to the running app process, then scan. The Dart/Flutter debugger alone may not attach a Java debugger. |
| `accessibilityUnrecognized` | Enable an accessibility service such as TalkBack, then scan. The example supplies no trusted-package allowlist, so enabled external services are reported with low confidence. Turn the service off afterward. |
| `screenshotTaken` | On Android 14/API 34 or later, take a device screenshot while the example is foregrounded. The signal is delivered by the event stream, not by a later snapshot. |
| `externalDisplay` | Connect or cast to a secondary display that Android exposes as a presentation display. Emulator virtual presentation displays can also produce this finding. |
| `signatureMismatch` | For a local-only test, pass a deliberately incorrect 64-character SHA-256 value to `MobileHardeningKit(expectedSigningCertificateSha256: ...)` in `example/lib/main.dart`, rebuild, and scan. Remove the test value afterward; do not commit it. |
| `root`, `instrumentation` | These require a test environment with a recognized root artifact/build tag or instrumentation library/listener. There is no reliable standard-emulator toggle; use only an isolated, authorized test device. |

To trigger `signatureMismatch`, temporarily replace the example's `_kit` initializer with this deliberately incorrect test fingerprint, then rebuild and scan:

```dart
final MobileHardeningKit _kit = MobileHardeningKit(
  expectedSigningCertificateSha256:
      '0000000000000000000000000000000000000000000000000000000000000000',
);
```

Make sure the test value differs from the app's actual signing-certificate fingerprint; a matching value will not trigger the finding.

Restore `MobileHardeningKit()` after the test; do not commit the test fingerprint.

Android does not expose a general screen-recording-active signal to ordinary apps. The Android screenshot callback only reports user screenshot events on API 34+ while the example's stream is subscribed.

### iOS

Run the example in the iOS Simulator or on a test device. The simulator reports `emulator` (the signal type is shared across platforms).

| Signal | Trigger |
| --- | --- |
| `debuggerAttach` | Run the app from Xcode using the Debug configuration, or attach Xcode's debugger to the running app, then tap **Scan now**. |
| `screenshotTaken` | On a physical iPhone/iPad, take a screenshot with the hardware buttons while the example is foregrounded. The notification arrives through the event stream. |
| `screenCaptureActive` | Start screen recording or screen mirroring from Control Center; stop it to observe the state change. |
| `externalDisplay` | Connect an external display or start AirPlay mirroring, then observe the stream (or scan while it is connected). |
| `jailbreak`, `instrumentation` | These need a jailbroken or instrumented test environment exposing one of the implementation's recognized artifacts. They have no standard Simulator trigger. |

The iOS `signatureMismatch` check only reports a missing Mach-O code-signature command; it cannot compare signing certificates. A normally signed iOS app cannot safely be made unsigned just to trigger this finding. iOS does not expose Android's accessibility/developer-setting checks.

### Test the separate screen-protection helper

The **Protect sensitive display content** switch is independent of signal detection. On Android it enables `FLAG_SECURE` for the app window, preventing screenshots while enabled. On iOS it blurs the app-switcher snapshot; it does not block screenshots or recording. Turn protection off before testing screenshot signals.

## Development

```sh
flutter pub get
flutter analyze
flutter test
cd example && flutter pub get && flutter build apk --debug
```

GitHub Actions analyzes and tests the package and example and builds the Android example for pull requests. Pushing a `v*` tag runs the same checks, builds a release APK, uploads it as a workflow artifact and GitHub Release asset, and uses `CHANGELOG.md` as the release notes. Update the changelog before every release tag.
