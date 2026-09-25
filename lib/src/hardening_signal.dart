/// Categories of client-side integrity and display observations.
enum HardeningSignalType {
  root,
  jailbreak,
  instrumentation,
  debuggerAttach,
  signatureMismatch,
  emulator,
  accessibilityUnrecognized,
  devModeEnabled,
  screenCaptureActive,
  screenshotTaken,
  externalDisplay,
}

/// A point-in-time observation. Metadata must not contain personal data.
class HardeningSignal {
  const HardeningSignal({
    required this.type,
    required this.observedAt,
    this.metadata = const <String, Object>{},
  });

  final HardeningSignalType type;
  final DateTime observedAt;
  final Map<String, Object> metadata;

  factory HardeningSignal.fromMap(Map<Object?, Object?> map) {
    final rawMetadata = map['metadata'];
    return HardeningSignal(
      type: HardeningSignalType.values.firstWhere(
        (value) => value.name == map['type'],
        orElse: () =>
            throw FormatException('Unknown signal type: ${map['type']}'),
      ),
      observedAt:
          DateTime.tryParse(map['observedAt'] as String? ?? '')?.toUtc() ??
              DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      metadata: rawMetadata is Map
          ? rawMetadata.map<String, Object>(
              (key, value) => MapEntry('$key', value as Object))
          : const <String, Object>{},
    );
  }

  @override
  bool operator ==(Object other) =>
      other is HardeningSignal &&
      type == other.type &&
      observedAt == other.observedAt &&
      _mapEquals(metadata, other.metadata);

  @override
  int get hashCode {
    final keys = metadata.keys.toList()..sort();
    return Object.hash(
      type,
      observedAt,
      Object.hashAll(keys.map((key) => Object.hash(key, metadata[key]))),
    );
  }

  static bool _mapEquals(Map<String, Object> a, Map<String, Object> b) {
    if (a.length != b.length) return false;
    for (final entry in a.entries) {
      if (b[entry.key] != entry.value) return false;
    }
    return true;
  }
}
