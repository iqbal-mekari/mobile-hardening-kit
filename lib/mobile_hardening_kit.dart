import 'dart:async';

import 'package:flutter/services.dart';

import 'src/hardening_signal.dart';
import 'src/screen_protection.dart';

export 'src/hardening_signal.dart';
export 'src/screen_protection.dart';

/// Client-side integrity observations for Android and iOS.
///
/// This API only detects and reports. Signals are heuristic and must not be
/// treated as a security boundary or used as the sole basis for blocking users.
class MobileHardeningKit {
  MobileHardeningKit({
    this.expectedSigningCertificateSha256,
    this.trustedAccessibilityPackages = const <String>{},
  });

  static const MethodChannel _methods = MethodChannel('mobile_hardening_kit');
  static const EventChannel _events =
      EventChannel('mobile_hardening_kit/events');

  /// Optional expected Android signing-certificate SHA-256, lowercase hex.
  /// Leave unset to omit the signature-mismatch check.
  final String? expectedSigningCertificateSha256;

  /// Android package IDs considered known-good accessibility services.
  /// Other enabled services may produce `accessibilityUnrecognized` signals.
  final Set<String> trustedAccessibilityPackages;

  /// Returns observations in native detection order, at most one per type.
  /// Unsupported checks are omitted.
  Future<List<HardeningSignal>> snapshot() async {
    final values =
        await _methods.invokeListMethod<Object?>('snapshot', <String, Object?>{
      if (expectedSigningCertificateSha256 != null)
        'expectedSigningCertificateSha256': expectedSigningCertificateSha256,
      'trustedAccessibilityPackages':
          trustedAccessibilityPackages.toList(growable: false),
    });
    return (values ?? const <Object?>[])
        .whereType<Map<Object?, Object?>>()
        .map(HardeningSignal.fromMap)
        .toList(growable: false);
  }

  /// Emits native display/capture observations as their state changes.
  ///
  /// Platforms only emit events they can observe reliably; this is not a
  /// periodic stream of integrity scans.
  Stream<HardeningSignal> get stream => _events
      .receiveBroadcastStream()
      .where((event) => event is Map)
      .map((event) => HardeningSignal.fromMap(event as Map<Object?, Object?>));

  /// Applies opt-in screen protection and reports what the platform applied.
  ///
  /// Each call replaces the previous request; pass [ScreenProtection.off] to
  /// clear it. Requested options the platform cannot apply are listed in
  /// [ScreenProtectionState.unavailable] as `<option>:<reason>`.
  ///
  /// Android: `blockCapture` applies FLAG_SECURE to the attached Flutter
  /// window (screenshots, recordings, casting, Recents); it is per window, so
  /// dialogs and separate native windows need their own handling.
  /// `obscureWhileCaptured` uses the API 35+ screen recording callback and
  /// `obscureAppSwitcher` the API 33+ Recents screenshot opt-out.
  ///
  /// iOS: `obscureAppSwitcher` blurs the app snapshot while inactive and
  /// `obscureWhileCaptured` covers the window while capture is active (reactive,
  /// first frames may leak). `blockCapture` is best-effort and not supported by
  /// Apple; never treat it as guaranteed.
  Future<ScreenProtectionState> setScreenProtection(
      ScreenProtection protection) async {
    final result = await _methods.invokeMapMethod<Object?, Object?>(
        'setScreenProtection', protection.toMap());
    if (result == null) {
      throw const FormatException('setScreenProtection returned no state');
    }
    return ScreenProtectionState.fromMap(result);
  }
}
