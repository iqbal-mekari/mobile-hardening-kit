# mobile_hardening_kit_example

This Flutter app demonstrates the `mobile_hardening_kit` detection and display-protection APIs, alongside a sample-only Play Integrity check. The kit reports positive heuristic findings; it does not block app flows. The separate Play verdicts and illustrative decision come from Google Play Integrity, verified by the Go backend. Neither client hints nor this example policy are production authorization.

## Play Integrity sample

The Go service is in [`../play_integrity_server/`](../play_integrity_server/). Configure its expected package name as `com.mekari.mobile_hardening_kit_example`, and configure Google Play Integrity API access using Application Default Credentials as described in that directory's README. Link the Play Integrity-enabled app in Play Console to a Google Cloud project, enable the Play Integrity API there, and use that linked **numeric cloud project number** (not the project ID) for the client define. The Android app uses the package ID `com.mekari.mobile_hardening_kit_example`.

Pass both compile-time defines when running the app:

```sh
flutter run \
  --dart-define=PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=123456789012 \
  --dart-define=PLAY_INTEGRITY_BACKEND_URL=https://integrity.example.com
```

`PLAY_INTEGRITY_BACKEND_URL` is the backend base URL; the app posts to `/check`. For local emulator development, bind the Go service to `0.0.0.0:8080` and use Android's host alias:

```sh
cd ../play_integrity_server
PLAY_INTEGRITY_PACKAGE_NAME=com.mekari.mobile_hardening_kit_example \
LISTEN_ADDR=0.0.0.0:8080 go run .
```

```sh
flutter run \
  --dart-define=PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=123456789012 \
  --dart-define=PLAY_INTEGRITY_BACKEND_URL=http://10.0.2.2:8080
```

For a physical device connected over USB, forward the backend port with `adb reverse tcp:8080 tcp:8080` and use `http://127.0.0.1:8080`. Cleartext HTTP is accepted only for debug loopback development hosts; use HTTPS elsewhere and for release builds.

The client requests a fresh kit snapshot for each check, binds its available/unavailable state and sorted snapshot signal names into the Play request hash, then sends the opaque integrity token to the backend. Tokens are never displayed. Event-stream history is shown separately and is not included as current state. An empty kit snapshot is unknown/unavailable, not a negative signal. The four sample reducers are `or` (default), `and`, `kitPrecedence`, and `providerPrecedence`; they do not change kit behavior. iOS and unconfigured setups retain all kit scanning and protection features, while the Play check is unavailable.

No successful Google verification is claimed by this example documentation. A successful check requires a correctly configured cloud project, Play-enabled app and eligible installation, provider readiness, backend credentials, and reachable backend. Emulator or sideload configurations may not receive a successful Play verdict.

## Xposed instrumentation probe

`xposed_probe/` is a standalone Android Gradle project; it is not included in the Flutter app's Gradle build. The APK is a no-hook module using the legacy Xposed API, scoped only to `com.mekari.mobile_hardening_kit_example`. Its entry point writes a log line when LSPosed loads it; it does not modify or hook app behavior.

The probe pins Android Gradle Plugin 7.3.0, which needs a Gradle 7.x build. Do not build it with the Flutter example's Gradle wrapper (`example/flutter/android/gradlew`, Gradle 9.1.0): the build fails with `DependencyHandler.module(Object)`. Build it with a locally installed Gradle 7.6.x (from [gradle.org/releases](https://gradle.org/releases/)). From the repository root, build and install it:

```sh
gradle -p example/flutter/xposed_probe :app:assembleDebug
adb -s DEVICE_ID install -r example/flutter/xposed_probe/app/build/outputs/apk/debug/app-debug.apk
```

In LSPosed Manager, enable **Mobile Hardening Xposed Probe** and confirm the Flutter example is its only selected scope. Force-stop and relaunch the example, then tap **Scan now**. To confirm the module loaded:

```sh
adb -s DEVICE_ID logcat -d -s LSPosed-Bridge
```

The scanner reports instrumentation only when a recognized file name (`libxposed`, `xposedbridge`, or `lsposed`) appears in the app process mappings. A bare `xposed` in a name is not matched. On the POCO F1 (Android 12, LSPosed 1.9.2), LSPosed logged the probe loading in the example, but the scan did not report `instrumentation`; this is a detector limitation, not evidence that the framework was inactive. With the 0.4.0 integrity monitor on the same device, loading the probe module produced only the low-confidence `artSegments` technique (`artTextSegments: 15`), which disappeared after the module was disabled; this is a heuristic, not LSPosed detection.

After uninstalling the probe and rescanning, the POCO still reported no `instrumentation` finding. The active-module scan had also returned no finding, so this confirms the clean state but does not demonstrate a detection transition.

Remove the probe after testing:

```sh
adb -s DEVICE_ID uninstall com.mekari.mobile_hardening_xposed_probe
```
