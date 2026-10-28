/// Opt-in window protection requested from the platform. Every option is
/// independent and disabled by default.
class ScreenProtection {
  const ScreenProtection({
    this.blockCapture = false,
    this.obscureWhileCaptured = false,
    this.obscureAppSwitcher = false,
  });

  /// Protection with every option disabled; clears earlier requests.
  static const off = ScreenProtection();

  /// Blank screenshots and recordings. Android applies FLAG_SECURE. iOS is
  /// best-effort and not supported by Apple.
  final bool blockCapture;

  /// Cover the window while the screen is being recorded or mirrored.
  final bool obscureWhileCaptured;

  /// Hide window content in the app switcher / Recents.
  final bool obscureAppSwitcher;

  Map<String, Object?> toMap() => <String, Object?>{
        'blockCapture': blockCapture,
        'obscureWhileCaptured': obscureWhileCaptured,
        'obscureAppSwitcher': obscureAppSwitcher,
      };

  @override
  bool operator ==(Object other) =>
      other is ScreenProtection &&
      blockCapture == other.blockCapture &&
      obscureWhileCaptured == other.obscureWhileCaptured &&
      obscureAppSwitcher == other.obscureAppSwitcher;

  @override
  int get hashCode =>
      Object.hash(blockCapture, obscureWhileCaptured, obscureAppSwitcher);
}

/// What the platform actually applied for a [ScreenProtection] request.
class ScreenProtectionState {
  ScreenProtectionState({
    required this.captureBlocked,
    required this.obscuresWhileCaptured,
    required this.obscuresAppSwitcher,
    List<String> unavailable = const <String>[],
  }) : unavailable = List<String>.unmodifiable(unavailable);

  /// Strictly decodes the native reply. Unknown keys are ignored; a missing or
  /// mistyped key throws [FormatException].
  factory ScreenProtectionState.fromMap(Map<Object?, Object?> map) {
    bool flag(String key) {
      final value = map[key];
      if (value is bool) return value;
      throw FormatException('Invalid screen protection field "$key": $value');
    }

    final rawUnavailable = map['unavailable'];
    if (rawUnavailable is! List || rawUnavailable.any((e) => e is! String)) {
      throw FormatException(
          'Invalid screen protection field "unavailable": $rawUnavailable');
    }
    return ScreenProtectionState(
      captureBlocked: flag('captureBlocked'),
      obscuresWhileCaptured: flag('obscuresWhileCaptured'),
      obscuresAppSwitcher: flag('obscuresAppSwitcher'),
      unavailable: rawUnavailable.cast<String>(),
    );
  }

  final bool captureBlocked;
  final bool obscuresWhileCaptured;
  final bool obscuresAppSwitcher;

  /// `<option>:<reason>` entries for requested options the platform could not
  /// apply. Unmodifiable.
  final List<String> unavailable;

  @override
  bool operator ==(Object other) =>
      other is ScreenProtectionState &&
      captureBlocked == other.captureBlocked &&
      obscuresWhileCaptured == other.obscuresWhileCaptured &&
      obscuresAppSwitcher == other.obscuresAppSwitcher &&
      _listEquals(unavailable, other.unavailable);

  @override
  int get hashCode => Object.hash(
        captureBlocked,
        obscuresWhileCaptured,
        obscuresAppSwitcher,
        Object.hashAll(unavailable),
      );

  static bool _listEquals(List<String> a, List<String> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
