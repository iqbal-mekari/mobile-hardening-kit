import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('mobile_hardening_kit');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test('snapshot decodes native findings and ignores non-map entries',
      () async {
    messenger.setMockMethodCallHandler(
        channel,
        (call) async => <Object?>[
              <String, Object?>{
                'type': 'root',
                'confidence': 'high',
                'observedAt': '2026-01-02T03:04:05.000Z',
                'metadata': <String, Object?>{'testKeys': true},
              },
              'invalid entry',
            ]);

    final signals = await MobileHardeningKit().snapshot();

    expect(signals, hasLength(1));
    expect(signals.single.type, HardeningSignalType.root);
    expect(signals.single.confidence, SignalConfidence.high);
    expect(signals.single.observedAt, DateTime.utc(2026, 1, 2, 3, 4, 5));
  });

  test(
      'snapshot rejects unknown native signal types instead of silently masking them',
      () async {
    messenger.setMockMethodCallHandler(
        channel,
        (call) async => <Object?>[
              <String, Object?>{
                'type': 'unknown',
                'confidence': 'high',
                'observedAt': '2026-01-02T03:04:05Z',
              },
            ]);

    expect(MobileHardeningKit().snapshot(), throwsFormatException);
  });

  test('signal decoder applies safe defaults for missing optional fields', () {
    final signal =
        HardeningSignal.fromMap(<Object?, Object?>{'type': 'emulator'});

    expect(signal.type, HardeningSignalType.emulator);
    expect(signal.confidence, SignalConfidence.low);
    expect(
        signal.observedAt, DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
    expect(signal.metadata, isEmpty);
  });

  test(
      'signal equality and hash code do not depend on metadata insertion order',
      () {
    final first = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      confidence: SignalConfidence.high,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'port': 27042, 'artifact': 'frida'},
    );
    final second = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      confidence: SignalConfidence.high,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'artifact': 'frida', 'port': 27042},
    );

    expect(first, second);
    expect(first.hashCode, second.hashCode);
  });
}
