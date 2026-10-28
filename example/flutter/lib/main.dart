import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

import 'play_sample_client.dart';

void main() => runApp(const HardeningExampleApp());

Map<String, Object?> _rawSignal(HardeningSignal signal) => <String, Object?>{
  'type': signal.type.name,
  'observedAt': signal.observedAt.toUtc().toIso8601String(),
  'metadata': signal.metadata,
};

String _formatSignals(Iterable<HardeningSignal> signals) =>
    const JsonEncoder.withIndent('  ')
        .convert(signals.map(_rawSignal).toList(growable: false));

const _policies = <String, String>{
  'or': 'Either available source',
  'and': 'Both available sources',
  'kitPrecedence': 'Prefer kit when available',
  'providerPrecedence': 'Prefer Play when available',
};
const _fullProtection = ScreenProtection(
  blockCapture: true,
  obscureWhileCaptured: true,
  obscureAppSwitcher: true,
);
const _riskTypes = <HardeningSignalType>{
  HardeningSignalType.root,
  HardeningSignalType.jailbreak,
  HardeningSignalType.instrumentation,
  HardeningSignalType.debuggerAttach,
  HardeningSignalType.emulator,
  HardeningSignalType.devModeEnabled,
};

const _integrityIntervals = <int, String>{5: '5 s', 30: '30 s'};
const _integrityEventLimit = 50;

class _IntegrityEntry {
  const _IntegrityEntry(this.id, this.signal);
  final int id;
  final HardeningSignal signal;
}

String _joined(Object? values) =>
    values is Iterable && values.isNotEmpty ? values.join(', ') : '-';

class HardeningExampleApp extends StatelessWidget {
  const HardeningExampleApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Mobile Hardening Kit',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
    home: const SignalExplorerPage(),
  );
}

class SignalExplorerPage extends StatefulWidget {
  const SignalExplorerPage({super.key, this.sampleClient});

  @visibleForTesting
  final PlaySampleClient? sampleClient;
  @override
  State<SignalExplorerPage> createState() => _SignalExplorerPageState();
}

class _SignalExplorerPageState extends State<SignalExplorerPage> {
  final MobileHardeningKit _kit = MobileHardeningKit();
  final List<HardeningSignal> _snapshotSignals = <HardeningSignal>[];
  final List<HardeningSignal> _streamSignals = <HardeningSignal>[];
  StreamSubscription<HardeningSignal>? _subscription;
  StreamSubscription<HardeningSignal>? _integritySubscription;
  final List<_IntegrityEntry> _integrityEvents = <_IntegrityEntry>[];
  int _integritySequence = 0;
  int _integrityIntervalSeconds = 30;
  String? _integrityError;
  bool _loading = true;
  bool _checking = false;
  bool _protectionEnabled = false;
  List<String> _protectionUnavailable = const <String>[];
  bool _kitSnapshotAvailable = false;
  String _policy = 'or';
  Object? _error;
  String? _checkError;
  Map<String, Object?>? _result;
  late final Uri? _backend = _backendUri();
  late final int? _projectNumber = _projectNumberValue();
  static final bool _isAndroid = !kIsWeb && Platform.isAndroid;

  static int? _projectNumberValue() {
    const value = String.fromEnvironment('PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER');
    final parsed = int.tryParse(value);
    return parsed != null && parsed > 0 ? parsed : null;
  }

  Uri? _backendUri() {
    const value = String.fromEnvironment('PLAY_INTEGRITY_BACKEND_URL');
    if (value.isEmpty) return null;
    final uri = Uri.tryParse(value);
    if (uri == null ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.query.isNotEmpty ||
        uri.fragment.isNotEmpty) {
      return null;
    }
    final loopback = const <String>{
      'localhost',
      '127.0.0.1',
      '10.0.2.2',
    }.contains(uri.host);
    if (uri.scheme != 'https' &&
        !(kDebugMode && loopback && uri.scheme == 'http')) {
      return null;
    }
    return uri;
  }

  @override
  void initState() {
    super.initState();
    _subscription = _kit.screenEvents.listen(
      (signal) {
        if (mounted) setState(() => _streamSignals.add(signal));
      },
      onError: (Object error) {
        if (mounted) setState(() => _error = error);
      },
    );
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final findings = await _kit.snapshot();
      if (!mounted) return;
      setState(() {
        _snapshotSignals
          ..clear()
          ..addAll(findings);
        _kitSnapshotAvailable = true;
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error;
        _loading = false;
        _kitSnapshotAvailable = false;
      });
    }
  }

  void _toggleIntegrityMonitor(bool enabled) {
    _integritySubscription?.cancel();
    _integritySubscription = null;
    setState(() => _integrityError = null);
    if (!enabled) return;
    _integritySubscription = _kit
        .integrityEvents(
          IntegrityMonitorConfig(
            interval: Duration(seconds: _integrityIntervalSeconds),
          ),
        )
        .listen(
          (signal) {
            if (!mounted) return;
            setState(() {
              _integrityEvents.insert(
                0,
                _IntegrityEntry(_integritySequence++, signal),
              );
              if (_integrityEvents.length > _integrityEventLimit) {
                _integrityEvents.removeLast();
              }
            });
          },
          onError: (Object error) {
            if (mounted) setState(() => _integrityError = '$error');
          },
        );
  }

  Future<void> _checkIntegrityNow() async {
    try {
      await _kit.checkIntegrityNow();
    } catch (error) {
      if (mounted) setState(() => _integrityError = '$error');
    }
  }

  Future<void> _toggleProtection(bool enabled) async {
    try {
      final state = await _kit.setScreenProtection(
        enabled ? _fullProtection : ScreenProtection.off,
      );
      if (mounted) {
        setState(() {
          _protectionEnabled = enabled;
          _protectionUnavailable = state.unavailable;
        });
      }
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _checkSample() async {
    if (_checking) return;
    setState(() {
      _checking = true;
      _checkError = null;
      _result = null;
    });
    bool available;
    List<String> types;
    try {
      final fresh = await _kit.snapshot();
      available = true;
      types = fresh.map((signal) => signal.type.name).toSet().toList()..sort();
      if (mounted) {
        setState(() {
          _snapshotSignals
            ..clear()
            ..addAll(fresh);
          _kitSnapshotAvailable = true;
        });
      }
    } catch (error) {
      available = false;
      types = <String>[];
      if (mounted) {
        setState(() {
          _error = error;
          _kitSnapshotAvailable = false;
        });
      }
    }
    try {
      if (!_isAndroid && widget.sampleClient == null) {
        throw const PlaySampleException(
          'Play Integrity is unavailable on this platform (Android only).',
        );
      }
      final client =
          widget.sampleClient ??
          PlaySampleClient(
            backend: _backend,
            cloudProjectNumber: _projectNumber,
          );
      final result = await client.check(
        policy: _policy,
        kitAvailable: available,
        kitSignals: types,
      );
      if (mounted) setState(() => _result = result);
    } catch (error) {
      if (mounted) setState(() => _checkError = '$error');
    } finally {
      if (mounted) setState(() => _checking = false);
    }
  }

  @override
  void dispose() {
    _subscription?.cancel();
    _integritySubscription?.cancel();
    if (_protectionEnabled) {
      unawaited(_kit.setScreenProtection(ScreenProtection.off));
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Mobile Hardening Kit')),
    body: ListView(
      padding: const EdgeInsets.all(16),
      children: <Widget>[
        const Text(
          'Client-side findings are heuristic signals. The kit reports only; it does not block flows.',
        ),
        const SizedBox(height: 12),
        SwitchListTile(
          key: const ValueKey<String>('protection-toggle'),
          contentPadding: EdgeInsets.zero,
          title: const Text('Protect sensitive display content'),
          subtitle: const Text('Capture, recording, and app switcher.'),
          value: _protectionEnabled,
          onChanged: _checking ? null : _toggleProtection,
        ),
        if (_protectionUnavailable.isNotEmpty)
          Text(
            'Unavailable: ${_protectionUnavailable.join(', ')}',
            key: const ValueKey<String>('protection-unavailable'),
          ),
        FilledButton.icon(
          onPressed: _loading || _checking ? null : _refresh,
          icon: const Icon(Icons.refresh),
          label: const Text('Scan now'),
        ),
        if (_loading) const LinearProgressIndicator(),
        if (_error != null)
          ListTile(
            leading: const Icon(Icons.error_outline),
            title: const Text('Signal collection failed'),
            subtitle: Text('$_error'),
          ),
        const SizedBox(height: 16),
        const Text('Snapshot response (raw JSON)'),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: SelectableText(
              _formatSignals(_snapshotSignals),
              key: const ValueKey<String>('snapshot-signals-json'),
            ),
          ),
        ),
        const SizedBox(height: 12),
        const Text('Event stream (raw JSON)'),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: SelectableText(
              _formatSignals(_streamSignals),
              key: const ValueKey<String>('stream-signals-json'),
            ),
          ),
        ),
        const Divider(height: 32),
        ..._integritySection(context),
        const Divider(height: 32),
        Text(
          'Play Integrity sample',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const Text(
          'Play verdicts are independently verified by the configured Go service. Kit hints are positive-only, client supplied, and not proof.',
        ),
        if (!_isAndroid)
          const ListTile(
            leading: Icon(Icons.info_outline),
            title: Text('Android only'),
            subtitle: Text(
              'Play Integrity is unavailable on this platform. Kit scans and display protection remain available.',
            ),
          ),
        if (_isAndroid && (_backend == null || _projectNumber == null))
          const ListTile(
            leading: Icon(Icons.settings_outlined),
            title: Text('Sample not configured'),
            subtitle: Text(
              'Set PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER and a valid HTTPS PLAY_INTEGRITY_BACKEND_URL (debug loopback HTTP is allowed).',
            ),
          ),
        if (_isAndroid &&
            _backend == null &&
            const String.fromEnvironment('PLAY_INTEGRITY_BACKEND_URL')
                .isNotEmpty)
          const Text(
            'Backend URL must use HTTPS, except debug loopback hosts.',
          ),
        DropdownButtonFormField<String>(
          key: const ValueKey<String>('policy-selector'),
          initialValue: _policy,
          isExpanded: true,
          decoration: const InputDecoration(labelText: 'Sample risk policy'),
          items: _policies.entries
              .map(
                (entry) => DropdownMenuItem<String>(
                  value: entry.key,
                  child: Text(
                    '${entry.key} — ${entry.value}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              )
              .toList(),
          onChanged: _checking
              ? null
              : (value) {
                  if (value != null) setState(() => _policy = value);
                },
        ),
        const SizedBox(height: 8),
        FilledButton.icon(
          key: const ValueKey<String>('check-sample'),
          onPressed: _checking || _loading ? null : _checkSample,
          icon: _checking
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.verified_user_outlined),
          label: Text(_checking ? 'Checking…' : 'Check sample'),
        ),
        if (_checking) const LinearProgressIndicator(),
        if (_checkError != null)
          ListTile(
            leading: const Icon(Icons.error_outline),
            title: const Text('Sample check unavailable'),
            subtitle: Text(_checkError!),
          ),
        if (_result != null) _resultView(_result!),
        if (_kitSnapshotAvailable &&
            !_snapshotSignals.any((signal) => _riskTypes.contains(signal.type)))
          const Text(
            'Kit risk: unavailable (no matching positive snapshot finding; this is not a negative result).',
          ),
        if (_kitSnapshotAvailable &&
            _snapshotSignals.any((signal) => _riskTypes.contains(signal.type)))
          const Text('Kit risk: detected (heuristic snapshot finding).'),
      ],
    ),
  );

  List<Widget> _integritySection(BuildContext context) => <Widget>[
    Text('Integrity monitor', style: Theme.of(context).textTheme.titleLarge),
    const Text(
      'Reports only new, changed, or cleared findings. Screen and display events stay on the event stream above.',
    ),
    SwitchListTile(
      key: const ValueKey<String>('integrity-monitor-toggle'),
      contentPadding: EdgeInsets.zero,
      title: const Text('Run integrity monitor'),
      subtitle: Text(
        _integritySubscription == null
            ? 'Stopped'
            : 'Running every $_integrityIntervalSeconds s',
      ),
      value: _integritySubscription != null,
      onChanged: _toggleIntegrityMonitor,
    ),
    DropdownButtonFormField<int>(
      key: const ValueKey<String>('integrity-interval-selector'),
      initialValue: _integrityIntervalSeconds,
      isExpanded: true,
      decoration: const InputDecoration(labelText: 'Check interval'),
      items: _integrityIntervals.entries
          .map(
            (entry) => DropdownMenuItem<int>(
              value: entry.key,
              child: Text(entry.value),
            ),
          )
          .toList(),
      onChanged: _integritySubscription != null
          ? null
          : (value) {
              if (value != null) {
                setState(() => _integrityIntervalSeconds = value);
              }
            },
    ),
    const SizedBox(height: 8),
    Row(
      children: <Widget>[
        FilledButton.icon(
          key: const ValueKey<String>('integrity-check-now'),
          onPressed: _integritySubscription == null ? null : _checkIntegrityNow,
          icon: const Icon(Icons.fact_check_outlined),
          label: const Text('Check now'),
        ),
        const SizedBox(width: 8),
        TextButton(
          key: const ValueKey<String>('integrity-events-clear'),
          onPressed: _integrityEvents.isEmpty
              ? null
              : () => setState(_integrityEvents.clear),
          child: const Text('Clear'),
        ),
      ],
    ),
    if (_integrityError != null)
      ListTile(
        key: const ValueKey<String>('integrity-error'),
        leading: const Icon(Icons.error_outline),
        title: const Text('Integrity monitor error'),
        subtitle: Text(_integrityError!),
      ),
    Text(
      'Integrity events: ${_integrityEvents.length}',
      key: const ValueKey<String>('integrity-events-count'),
    ),
    if (_integrityEvents.isEmpty)
      const Text(
        'No integrity events yet. Findings appear here when they are detected, change, or clear.',
        key: ValueKey<String>('integrity-events-empty'),
      ),
    Column(
      key: const ValueKey<String>('integrity-events-list'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: _integrityEvents.map(_integrityTile).toList(),
    ),
  ];

  Widget _integrityTile(_IntegrityEntry entry) {
    final signal = entry.signal;
    final metadata = signal.metadata;
    final prefix = 'integrity-event-${entry.id}';
    return Card(
      key: ValueKey<String>(prefix),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(
              '${signal.type.name} · ${metadata['change'] ?? '-'}',
              key: ValueKey<String>('$prefix-title'),
              style: Theme.of(context).textTheme.titleSmall,
            ),
            Text(
              'type: ${signal.type.name}',
              key: ValueKey<String>('$prefix-type'),
            ),
            Text(
              'change: ${metadata['change'] ?? '-'}',
              key: ValueKey<String>('$prefix-change'),
            ),
            Text(
              'trigger: ${metadata['trigger'] ?? '-'}',
              key: ValueKey<String>('$prefix-trigger'),
            ),
            Text(
              'techniques: ${_joined(metadata['techniques'])}',
              key: ValueKey<String>('$prefix-techniques'),
            ),
            Text(
              'artifacts: ${_joined(metadata['artifacts'])}',
              key: ValueKey<String>('$prefix-artifacts'),
            ),
            Text(
              'observedAt: ${signal.observedAt.toUtc().toIso8601String()}',
              key: ValueKey<String>('$prefix-observedAt'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _resultView(Map<String, Object?> result) {
    final verdicts = result['verdicts'] as Map;
    final risk = result['risk'] as Map;
    final reasons = result['reasons'];
    return Card(
      key: const ValueKey<String>('sample-result'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text('Illustrative sample decision: ${result['decision']}'),
            Text(
              'Verification: ${result['verification']} · policy: ${result['policy']}',
            ),
            Text(
              'App recognition: ${verdicts['appRecognition'] ?? 'unavailable'}',
            ),
            Text('App licensing: ${verdicts['appLicensing'] ?? 'unavailable'}'),
            Text(
              'Device recognition: ${verdicts['deviceRecognition'] ?? 'unavailable'}',
            ),
            Text(
              'Kit risk: ${risk['kit'] ?? 'unavailable'} · Play risk: ${risk['provider'] ?? 'unavailable'} · combined: ${risk['combined'] ?? 'unavailable'}',
            ),
            if (reasons is List) ...reasons.whereType<String>().map(Text.new),
            const Text(
              'Example policy only; client hints are untrusted and this is not production authorization.',
            ),
          ],
        ),
      ),
    );
  }
}
