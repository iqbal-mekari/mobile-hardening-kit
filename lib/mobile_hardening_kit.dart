import 'dart:async';

import 'package:flutter/services.dart';

import 'src/hardening_signal.dart';

export 'src/hardening_signal.dart';

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
  /// Other enabled services are reported with low confidence.
  final Set<String> trustedAccessibilityPackages;

  /// Returns all currently detected findings. Unsupported checks are omitted.
  Future<Set<HardeningSignal>> snapshot() async {
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
        .toSet();
  }

  /// Emits native display/capture observations as their state changes.
  ///
  /// Platforms only emit events they can observe reliably; this is not a
  /// periodic stream of integrity scans.
  Stream<HardeningSignal> get stream => _events
      .receiveBroadcastStream()
      .where((event) => event is Map)
      .map((event) => HardeningSignal.fromMap(event as Map<Object?, Object?>));

  /// Enables or disables per-window screenshot protection.
  ///
  /// Android applies FLAG_SECURE to the attached Flutter window. iOS obscures
  /// the app snapshot while backgrounded. Disabled by default.
  Future<void> setScreenProtectionEnabled(bool enabled) => _methods
          .invokeMethod<void>('setScreenProtectionEnabled', <String, Object?>{
        'enabled': enabled,
      });
}
