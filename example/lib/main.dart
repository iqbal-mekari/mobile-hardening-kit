import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

void main() => runApp(const HardeningExampleApp());

class HardeningExampleApp extends StatelessWidget {
  const HardeningExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Mobile Hardening Kit',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        home: const SignalExplorerPage(),
      );
}

class SignalExplorerPage extends StatefulWidget {
  const SignalExplorerPage({super.key});

  @override
  State<SignalExplorerPage> createState() => _SignalExplorerPageState();
}

class _SignalExplorerPageState extends State<SignalExplorerPage> {
  final MobileHardeningKit _kit = MobileHardeningKit();
  final Set<HardeningSignal> _signals = <HardeningSignal>{};
  StreamSubscription<HardeningSignal>? _subscription;
  bool _loading = true;
  bool _protectionEnabled = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _subscription = _kit.stream.listen(
      (signal) {
        if (mounted) setState(() => _signals.add(signal));
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
        _signals
          ..clear()
          ..addAll(findings);
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error;
        _loading = false;
      });
    }
  }

  Future<void> _toggleProtection(bool enabled) async {
    try {
      await _kit.setScreenProtectionEnabled(enabled);
      if (mounted) setState(() => _protectionEnabled = enabled);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  @override
  void dispose() {
    _subscription?.cancel();
    if (_protectionEnabled) unawaited(_kit.setScreenProtectionEnabled(false));
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
              contentPadding: EdgeInsets.zero,
              title: const Text('Protect sensitive display content'),
              subtitle: const Text(
                  'Android FLAG_SECURE; iOS app-switcher snapshot blur.'),
              value: _protectionEnabled,
              onChanged: _toggleProtection,
            ),
            FilledButton.icon(
              onPressed: _loading ? null : _refresh,
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
            if (!_loading && _signals.isEmpty && _error == null)
              const ListTile(
                leading: Icon(Icons.verified_user_outlined),
                title: Text('No signals detected'),
                subtitle:
                    Text('This is not proof that the device is uncompromised.'),
              ),
            ..._signals.map((signal) => Card(
                  child: ListTile(
                    leading: const Icon(Icons.shield_outlined),
                    title: Text(signal.type.name),
                    subtitle: Text(
                      '${signal.confidence.name} confidence · ${signal.observedAt.toLocal()}\n${signal.metadata}',
                    ),
                    isThreeLine: signal.metadata.isNotEmpty,
                  ),
                )),
          ],
        ),
      );
}
