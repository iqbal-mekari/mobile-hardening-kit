import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('mobile_hardening_kit');
  const eventChannel = EventChannel('mobile_hardening_kit/events');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
    messenger.setMockStreamHandler(eventChannel, null);
  });

  test('snapshot preserves native order and decodes confidence-free records',
      () async {
    messenger.setMockMethodCallHandler(
        channel,
        (call) async => <Object?>[
              <String, Object?>{
                'type': 'root',
                'observedAt': '2026-01-02T03:04:05.000Z',
                'metadata': <String, Object?>{'testKeys': true},
              },
              <String, Object?>{
                'type': 'instrumentation',
                'observedAt': '2026-01-02T03:04:06.000Z',
                'metadata': <String, Object?>{
                  'artifacts': <String>['frida'],
                  'tracerPort': 0,
                },
              },
              'invalid entry',
            ]);

    final List<HardeningSignal> signals = await MobileHardeningKit().snapshot();

    expect(signals.map((signal) => signal.type).toList(), <HardeningSignalType>[
      HardeningSignalType.root,
      HardeningSignalType.instrumentation,
    ]);
    expect(signals.first.metadata, <String, Object>{'testKeys': true});
    expect(signals.last.metadata['artifacts'], <String>['frida']);
    expect(signals.first.observedAt, DateTime.utc(2026, 1, 2, 3, 4, 5));
  });

  test(
      'snapshot rejects unknown native signal types instead of silently masking them',
      () async {
    messenger.setMockMethodCallHandler(
        channel,
        (call) async => <Object?>[
              <String, Object?>{
                'type': 'unknown',
                'observedAt': '2026-01-02T03:04:05Z',
              },
            ]);

    expect(MobileHardeningKit().snapshot(), throwsFormatException);
  });

  test('snapshot returns an empty list when native returns null', () async {
    messenger.setMockMethodCallHandler(channel, (call) async => null);

    expect(await MobileHardeningKit().snapshot(), isEmpty);
  });

  test('stream skips non-map events and decodes valid observations', () async {
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(
        onListen: (arguments, events) {
          events.success('unrecognized payload');
          events.success(<String, Object?>{
            'type': 'externalDisplay',
            'observedAt': '2026-01-02T03:04:05Z',
            'metadata': <String, Object?>{'connected': false},
          });
        },
      ),
    );

    final signals = await MobileHardeningKit().stream.take(1).toList();

    expect(signals, hasLength(1));
    expect(signals.single.type, HardeningSignalType.externalDisplay);
    expect(signals.single.metadata, <String, Object>{'connected': false});
  });

  test('stream reports unknown signal types as format errors', () async {
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(
        onListen: (arguments, events) {
          events.success(<String, Object?>{
            'type': 'unknown',
            'observedAt': '2026-01-02T03:04:05Z',
          });
        },
      ),
    );

    await expectLater(
      MobileHardeningKit().stream,
      emitsError(isA<FormatException>()),
    );
  });

  test('signal decoder applies safe defaults for missing optional fields', () {
    final signal =
        HardeningSignal.fromMap(<Object?, Object?>{'type': 'emulator'});

    expect(signal.type, HardeningSignalType.emulator);
    expect(
        signal.observedAt, DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
    expect(signal.metadata, isEmpty);
  });

  test('signal decoder defaults invalid timestamps and non-map metadata', () {
    final signal = HardeningSignal.fromMap(<Object?, Object?>{
      'type': 'emulator',
      'observedAt': 'not-a-timestamp',
      'metadata': <String>['not', 'a', 'map'],
    });

    expect(
        signal.observedAt, DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
    expect(signal.metadata, isEmpty);
  });

  test('signal decoder normalizes offset timestamps and metadata keys', () {
    final signal = HardeningSignal.fromMap(<Object?, Object?>{
      'type': 'emulator',
      'observedAt': '2026-01-02T03:04:05+02:00',
      'metadata': <Object?, Object?>{7: 'seven'},
    });

    expect(signal.observedAt, DateTime.utc(2026, 1, 2, 1, 4, 5));
    expect(signal.observedAt.isUtc, isTrue);
    expect(signal.metadata, <String, Object>{'7': 'seven'});
  });

  test(
      'signal equality and hash code do not depend on metadata insertion order',
      () {
    final first = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'port': 27042, 'artifact': 'frida'},
    );
    final second = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'artifact': 'frida', 'port': 27042},
    );

    expect(first, second);
    expect(first.hashCode, second.hashCode);
  });

  test(
      'signal equality distinguishes type, timestamp, metadata, and other objects',
      () {
    final signal = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'artifact': 'frida'},
    );

    expect(signal == Object(), isFalse);
    expect(
      signal,
      isNot(HardeningSignal(
        type: HardeningSignalType.root,
        observedAt: DateTime.utc(2026),
        metadata: const <String, Object>{'artifact': 'frida'},
      )),
    );
    expect(
      signal,
      isNot(HardeningSignal(
        type: HardeningSignalType.instrumentation,
        observedAt: DateTime.utc(2026, 1, 2),
        metadata: const <String, Object>{'artifact': 'frida'},
      )),
    );
    expect(
      signal,
      isNot(HardeningSignal(
        type: HardeningSignalType.instrumentation,
        observedAt: DateTime.utc(2026),
        metadata: const <String, Object>{'artifact': 'xposed'},
      )),
    );
  });

  test('snapshot sends configured certificate and trusted packages', () async {
    MethodCall? received;
    messenger.setMockMethodCallHandler(channel, (call) async {
      received = call;
      return <Object?>[];
    });

    await MobileHardeningKit(
      expectedSigningCertificateSha256: 'ab:cd',
      trustedAccessibilityPackages: const <String>{'com.trusted'},
    ).snapshot();

    expect(received?.method, 'snapshot');
    expect(received?.arguments, <String, Object?>{
      'expectedSigningCertificateSha256': 'ab:cd',
      'trustedAccessibilityPackages': <String>['com.trusted'],
    });
  });

  test('snapshot omits the certificate argument when unset', () async {
    MethodCall? received;
    messenger.setMockMethodCallHandler(channel, (call) async {
      received = call;
      return <Object?>[];
    });

    await MobileHardeningKit().snapshot();

    expect(received?.arguments, <String, Object?>{
      'trustedAccessibilityPackages': <String>[],
    });
  });

  Map<String, Object?> stateReply() => <String, Object?>{
        'captureBlocked': true,
        'obscuresWhileCaptured': false,
        'obscuresAppSwitcher': true,
        'unavailable': <Object?>['obscureWhileCaptured:apiLevel'],
        'extra': 'ignored',
      };

  test('setScreenProtection sends options and decodes the applied state',
      () async {
    MethodCall? received;
    messenger.setMockMethodCallHandler(channel, (call) async {
      received = call;
      return stateReply();
    });

    final state = await MobileHardeningKit().setScreenProtection(
      const ScreenProtection(blockCapture: true, obscureAppSwitcher: true),
    );

    expect(received?.method, 'setScreenProtection');
    expect(received?.arguments, <String, Object?>{
      'blockCapture': true,
      'obscureWhileCaptured': false,
      'obscureAppSwitcher': true,
    });
    expect(state.captureBlocked, isTrue);
    expect(state.obscuresWhileCaptured, isFalse);
    expect(state.obscuresAppSwitcher, isTrue);
    expect(state.unavailable, <String>['obscureWhileCaptured:apiLevel']);
    expect(() => state.unavailable.add('x'), throwsUnsupportedError);
  });

  test('setScreenProtection(off) sends all-false options', () async {
    MethodCall? received;
    messenger.setMockMethodCallHandler(channel, (call) async {
      received = call;
      return <String, Object?>{
        'captureBlocked': false,
        'obscuresWhileCaptured': false,
        'obscuresAppSwitcher': false,
        'unavailable': <Object?>[],
      };
    });

    final state =
        await MobileHardeningKit().setScreenProtection(ScreenProtection.off);

    expect(received?.arguments, <String, Object?>{
      'blockCapture': false,
      'obscureWhileCaptured': false,
      'obscureAppSwitcher': false,
    });
    expect(state.unavailable, isEmpty);
    expect(state.captureBlocked, isFalse);
  });

  test('setScreenProtection rejects a null native result', () {
    messenger.setMockMethodCallHandler(channel, (call) async => null);

    expect(MobileHardeningKit().setScreenProtection(ScreenProtection.off),
        throwsFormatException);
  });

  test('setScreenProtection propagates platform errors', () {
    messenger.setMockMethodCallHandler(
        channel, (call) async => throw PlatformException(code: 'unavailable'));

    expect(MobileHardeningKit().setScreenProtection(ScreenProtection.off),
        throwsA(isA<PlatformException>()));
  });

  test('state decoder rejects missing and mistyped keys', () {
    for (final key in stateReply().keys.where((key) => key != 'extra')) {
      expect(
        () => ScreenProtectionState.fromMap(stateReply()..remove(key)),
        throwsFormatException,
        reason: 'missing $key',
      );
    }
    for (final key in <String>[
      'captureBlocked',
      'obscuresWhileCaptured',
      'obscuresAppSwitcher',
    ]) {
      expect(
        () => ScreenProtectionState.fromMap(stateReply()..[key] = 'yes'),
        throwsFormatException,
        reason: 'mistyped $key',
      );
    }
    expect(
      () => ScreenProtectionState.fromMap(stateReply()..['unavailable'] = 'x'),
      throwsFormatException,
    );
    expect(
      () => ScreenProtectionState.fromMap(
          stateReply()..['unavailable'] = <Object?>[1]),
      throwsFormatException,
    );
  });

  test('ScreenProtection defaults, off, toMap, equality, and hash code', () {
    const all = ScreenProtection(
      blockCapture: true,
      obscureWhileCaptured: true,
      obscureAppSwitcher: true,
    );

    expect(ScreenProtection.off, const ScreenProtection());
    expect(ScreenProtection.off.toMap().values, everyElement(isFalse));
    expect(all.toMap().values, everyElement(isTrue));
    expect(
        all,
        const ScreenProtection(
          blockCapture: true,
          obscureWhileCaptured: true,
          obscureAppSwitcher: true,
        ));
    expect(all.hashCode, all.hashCode);
    expect(all.hashCode, isNot(ScreenProtection.off.hashCode));
    expect(all == Object(), isFalse);
    expect(ScreenProtection.off,
        isNot(const ScreenProtection(blockCapture: true)));
    expect(ScreenProtection.off,
        isNot(const ScreenProtection(obscureWhileCaptured: true)));
    expect(ScreenProtection.off,
        isNot(const ScreenProtection(obscureAppSwitcher: true)));
  });

  test('ScreenProtectionState equality and hash code', () {
    ScreenProtectionState make({
      bool blocked = true,
      bool whileCaptured = false,
      bool switcher = true,
      List<String> unavailable = const <String>['a:b'],
    }) =>
        ScreenProtectionState(
          captureBlocked: blocked,
          obscuresWhileCaptured: whileCaptured,
          obscuresAppSwitcher: switcher,
          unavailable: unavailable,
        );

    expect(make(), make());
    expect(make().hashCode, make().hashCode);
    expect(make() == Object(), isFalse);
    expect(make(), isNot(make(blocked: false)));
    expect(make(), isNot(make(whileCaptured: true)));
    expect(make(), isNot(make(switcher: false)));
    expect(make(), isNot(make(unavailable: const <String>[])));
    expect(make(), isNot(make(unavailable: const <String>['a:c'])));
    expect(make(unavailable: const <String>[]).unavailable, isEmpty);
  });
}
