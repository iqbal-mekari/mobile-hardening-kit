# mobile_hardening_kit_example

Demonstrates how to use the mobile_hardening_kit plugin.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://docs.flutter.dev/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://docs.flutter.dev/cookbook)

For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.

## Xposed instrumentation probe

`xposed_probe/` is a standalone Android Gradle project; it is not included in the Flutter app's Gradle build. The APK is a no-hook module using the legacy Xposed API, scoped only to `com.mekari.mobile_hardening_kit_example`. Its entry point writes a log line when LSPosed loads it; it does not modify or hook app behavior.

From the repository root, build and install it:

```sh
./example/flutter/android/gradlew -p example/flutter/xposed_probe :app:assembleDebug
adb -s DEVICE_ID install -r example/flutter/xposed_probe/app/build/outputs/apk/debug/app-debug.apk
```

In LSPosed Manager, enable **Mobile Hardening Xposed Probe** and confirm the Flutter example is its only selected scope. Force-stop and relaunch the example, then tap **Scan now**. To confirm the module loaded:

```sh
adb -s DEVICE_ID logcat -d -s LSPosed-Bridge
```

The scanner reports instrumentation only when a recognized `xposed`/`lsposed` name appears in the app process mappings. On the POCO F1 (Android 12, LSPosed 1.9.2), LSPosed logged the probe loading in the example, but the scan did not report `instrumentation`; this is a detector limitation, not evidence that the framework was inactive.

After uninstalling the probe and rescanning, the POCO still reported no `instrumentation` finding. The active-module scan had also returned no finding, so this confirms the clean state but does not demonstrate a detection transition.

Remove the probe after testing:

```sh
adb -s DEVICE_ID uninstall com.mekari.mobile_hardening_xposed_probe
```
