/// Schedule for the runtime integrity monitor started by
/// `MobileHardeningKit.integrityEvents`.
///
/// The monitor is report-only and heuristic; see `integrityEvents` for what
/// each pass covers.
class IntegrityMonitorConfig {
  /// Creates a monitor schedule.
  const IntegrityMonitorConfig({
    this.interval = const Duration(seconds: 30),
    this.checkOnResume = true,
  });

  /// The smallest interval sent to the platform; shorter values are raised.
  static const Duration minimumInterval = Duration(seconds: 5);

  /// The largest interval sent to the platform; longer values are lowered.
  static const Duration maximumInterval = Duration(hours: 24);

  /// Time between runtime-attach checks (instrumentation and debugger) while
  /// the app is in the foreground. Values outside [minimumInterval] to
  /// [maximumInterval] (5 seconds to 24 hours) are clamped when sent.
  final Duration interval;

  /// Whether a full pass also runs each time the app returns to the
  /// foreground.
  final bool checkOnResume;

  /// Listen arguments for the native `integrity_events` channel:
  /// `{intervalMs, checkOnResume}` with the interval clamped to 5 s - 24 h.
  Map<String, Object?> toMap() => <String, Object?>{
    'intervalMs':
        (interval < minimumInterval
                ? minimumInterval
                : interval > maximumInterval
                ? maximumInterval
                : interval)
            .inMilliseconds,
    'checkOnResume': checkOnResume,
  };

  @override
  bool operator ==(Object other) =>
      other is IntegrityMonitorConfig &&
      interval == other.interval &&
      checkOnResume == other.checkOnResume;

  @override
  int get hashCode => Object.hash(interval, checkOnResume);

  @override
  String toString() =>
      'IntegrityMonitorConfig(interval: $interval, checkOnResume: $checkOnResume)';
}
