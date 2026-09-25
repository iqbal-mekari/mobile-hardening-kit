# Changelog

All notable changes to this project are documented here.

## [0.1.0] - 2026-09-25

### Added
- Shared Flutter API for point-in-time integrity signal snapshots and native display/capture transition events.
- Android root, instrumentation, debugger, optional signer-fingerprint, emulator, accessibility, developer-mode, screenshot (Android 14+), and external-display collectors.
- iOS jailbreak, instrumentation, debugger, simulator, code-signature-presence, capture, screenshot, and external-display collectors.
- Opt-in Android `FLAG_SECURE` and iOS app-switcher snapshot obscuring.
- Example app, Dart tests, pull-request checks, tagged release APK artifact, and changelog-backed GitHub Release notes.

### Limitations
- Signals are heuristic, may miss tampering, and must not be treated as an enforcement boundary.
- iOS apps cannot read a signing-certificate fingerprint from the sandbox; the kit only checks for the executable's code-signature load command.
- iOS does not expose screenshot prevention; its helper only obscures the app-switcher snapshot.
- Android cannot reliably enumerate screen-recording apps; screenshot event callbacks require Android 14+.
