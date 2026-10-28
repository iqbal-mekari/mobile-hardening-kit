import 'dart:async';

import 'package:flutter/services.dart';

import 'src/hardening_signal.dart';
import 'src/integrity_monitor_config.dart';
import 'src/screen_protection.dart';
import 'src/shared_event_stream.dart';

export 'src/hardening_signal.dart';
export 'src/integrity_monitor_config.dart';
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
  static const EventChannel _events = EventChannel(
    'mobile_hardening_kit/events',
  );
  static const EventChannel _integrityEvents = EventChannel(
    'mobile_hardening_kit/integrity_events',
  );

  // Channels are process-wide, so native subscriptions are shared across all
  // listeners and all kit instances.
  static final SharedEventStream _screenShared = SharedEventStream(_events);
  static final SharedEventStream _integrityShared = SharedEventStream(
    _integrityEvents,
    arguments: () => _integritySession?.arguments,
  );
  static _IntegritySession? _integritySession;

  /// Optional expected Android signing-certificate SHA-256, lowercase hex.
  /// Leave unset to omit the signature-mismatch check.
  final String? expectedSigningCertificateSha256;

  /// Android package IDs considered known-good accessibility services.
  /// Other enabled services may produce `accessibilityUnrecognized` signals.
  final Set<String> trustedAccessibilityPackages;

  /// Returns observations in native detection order, at most one per type.
  /// Unsupported checks are omitted.
  Future<List<HardeningSignal>> snapshot() async {
    final values = await _methods.invokeListMethod<Object?>(
      'snapshot',
      <String, Object?>{
        if (expectedSigningCertificateSha256 != null)
          'expectedSigningCertificateSha256': expectedSigningCertificateSha256,
        'trustedAccessibilityPackages': trustedAccessibilityPackages.toList(
          growable: false,
        ),
      },
    );
    return (values ?? const <Object?>[])
        .whereType<Map<Object?, Object?>>()
        .map(HardeningSignal.fromMap)
        .toList(growable: false);
  }

  /// Emits native screenshot, screen-capture, and external-display
  /// observations as their state changes.
  ///
  /// Platforms only emit events they can observe reliably; this is not a
  /// periodic stream of integrity scans (see [integrityEvents]). All listeners,
  /// on this and every other kit instance, share one native subscription, which
  /// is cancelled when the last listener cancels. Heuristic and report-only.
  Stream<HardeningSignal> get screenEvents => _screenShared.stream;

  /// Deprecated alias of [screenEvents].
  @Deprecated('Use screenEvents; removed in 0.5.0')
  Stream<HardeningSignal> get stream => screenEvents;

  /// Runs the runtime integrity monitor while the returned stream has
  /// listeners and emits only findings that are new, changed, or cleared.
  ///
  /// The first pass (`trigger: start`) reports every current finding as
  /// `metadata.change == 'detected'`. Later passes report `detected`,
  /// `changed`, or `cleared` (a cleared event carries the last known metadata).
  /// Every event also carries `metadata.trigger` (`start`, `resume`,
  /// `interval`, `imageLoad` on iOS, or `manual`) and `metadata.techniques`,
  /// the evidence sources behind the finding, so consumers can weight them.
  ///
  /// Start, resume, and manual passes run every [snapshot] check; interval and
  /// image-load passes cover only `instrumentation` and `debuggerAttach`, and
  /// never clear other types. [expectedSigningCertificateSha256] and
  /// [trustedAccessibilityPackages] of this instance apply to monitor passes.
  ///
  /// The monitor only observes the foreground app, is heuristic, and can be
  /// evaded by a tool that is already attached; it never blocks or alters the
  /// app and must not be treated as a security boundary.
  ///
  /// All listeners share one native monitor session, adopted from whichever
  /// stream gets the first listener. While it has listeners, calling this with
  /// a different [config], or from an instance with a different signing
  /// certificate or trusted accessibility packages, throws a [StateError], and
  /// listening to a previously obtained stream of a different session fails
  /// that subscription with a [StateError]. After the last listener cancels, a
  /// new configuration is allowed.
  Stream<HardeningSignal> integrityEvents([
    IntegrityMonitorConfig config = const IntegrityMonitorConfig(),
  ]) {
    final requested = _IntegritySession(
      config,
      expectedSigningCertificateSha256,
      trustedAccessibilityPackages,
    );
    if (_integrityShared.hasListeners && _integritySession != requested) {
      throw StateError(_sessionConflict);
    }
    // The stream is bound to this call's session. Native monitoring starts
    // with the session of the first listener, never with a later caller's, so
    // a certificate or package list passed here cannot be silently dropped.
    return Stream<HardeningSignal>.multi((controller) {
      if (_integrityShared.hasListeners && _integritySession != requested) {
        controller
          ..addErrorSync(StateError(_sessionConflict))
          ..closeSync();
        return;
      }
      _integritySession = requested;
      final subscription = _integrityShared.stream.listen(
        controller.addSync,
        onError: controller.addErrorSync,
        onDone: controller.closeSync,
      );
      controller.onCancel = subscription.cancel;
    }, isBroadcast: true);
  }

  static const String _sessionConflict =
      'integrityEvents is already active with a different configuration; '
      'cancel all listeners before changing it.';

  /// Runs one monitor pass now, for example before a sensitive action.
  ///
  /// Results arrive on [integrityEvents] with `metadata.trigger == 'manual'`.
  /// Does nothing when the monitor is not running.
  Future<void> checkIntegrityNow() =>
      _methods.invokeMethod<void>('checkIntegrityNow');

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
    ScreenProtection protection,
  ) async {
    final result = await _methods.invokeMapMethod<Object?, Object?>(
      'setScreenProtection',
      protection.toMap(),
    );
    if (result == null) {
      throw const FormatException('setScreenProtection returned no state');
    }
    return ScreenProtectionState.fromMap(result);
  }
}

/// Monitor settings that must match across listeners of the shared session.
class _IntegritySession {
  _IntegritySession(
    this.config,
    this.expectedSigningCertificateSha256,
    Set<String> trustedAccessibilityPackages,
  ) : trustedAccessibilityPackages = (trustedAccessibilityPackages.toList()
        ..sort());

  final IntegrityMonitorConfig config;
  final String? expectedSigningCertificateSha256;
  final List<String> trustedAccessibilityPackages;

  Map<String, Object?> get arguments => <String, Object?>{
    ...config.toMap(),
    if (expectedSigningCertificateSha256 != null)
      'expectedSigningCertificateSha256': expectedSigningCertificateSha256,
    'trustedAccessibilityPackages': trustedAccessibilityPackages,
  };

  @override
  bool operator ==(Object other) =>
      other is _IntegritySession &&
      config == other.config &&
      expectedSigningCertificateSha256 ==
          other.expectedSigningCertificateSha256 &&
      trustedAccessibilityPackages.join('\n') ==
          other.trustedAccessibilityPackages.join('\n');

  @override
  int get hashCode => Object.hash(
    config,
    expectedSigningCertificateSha256,
    Object.hashAll(trustedAccessibilityPackages),
  );
}
