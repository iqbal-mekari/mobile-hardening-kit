import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit/mobile_hardening_kit.dart';

class _NativeCalls {
  final List<Object?> listens = <Object?>[];
  int cancels = 0;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('mobile_hardening_kit');
  const eventChannel = EventChannel('mobile_hardening_kit/events');
  const integrityChannel = EventChannel(
    'mobile_hardening_kit/integrity_events',
  );
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
    messenger.setMockStreamHandler(eventChannel, null);
    messenger.setMockStreamHandler(integrityChannel, null);
  });

  // Counts native listen/cancel calls and records listen arguments.
  _NativeCalls mockNative(
    EventChannel target, {
    void Function(MockStreamHandlerEventSink events)? onListen,
  }) {
    final calls = _NativeCalls();
    messenger.setMockStreamHandler(
      target,
      MockStreamHandler.inline(
        onListen: (arguments, events) {
          calls.listens.add(arguments);
          onListen?.call(events);
        },
        onCancel: (arguments) => calls.cancels++,
      ),
    );
    return calls;
  }

  Map<String, Object?> integrityEvent(Map<String, Object?> metadata) =>
      <String, Object?>{
        'type': 'instrumentation',
        'observedAt': '2026-01-02T03:04:05.000Z',
        'metadata': metadata,
      };

  Future<void> pump() => Future<void>.delayed(Duration.zero);

  test(
    'snapshot preserves native order and decodes confidence-free records',
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
        ],
      );

      final List<HardeningSignal> signals = await MobileHardeningKit()
          .snapshot();

      expect(
        signals.map((signal) => signal.type).toList(),
        <HardeningSignalType>[
          HardeningSignalType.root,
          HardeningSignalType.instrumentation,
        ],
      );
      expect(signals.first.metadata, <String, Object>{'testKeys': true});
      expect(signals.last.metadata['artifacts'], <String>['frida']);
      expect(signals.first.observedAt, DateTime.utc(2026, 1, 2, 3, 4, 5));
    },
  );

  test('snapshot rejects unknown native signal types instead of silently masking them', () async {
    messenger.setMockMethodCallHandler(
      channel,
      (call) async => <Object?>[
        <String, Object?>{
          'type': 'unknown',
          'observedAt': '2026-01-02T03:04:05Z',
        },
      ],
    );

    expect(MobileHardeningKit().snapshot(), throwsFormatException);
  });

  test('snapshot returns an empty list when native returns null', () async {
    messenger.setMockMethodCallHandler(channel, (call) async => null);

    expect(await MobileHardeningKit().snapshot(), isEmpty);
  });

  test(
    'screenEvents skips non-map events and decodes valid observations',
    () async {
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

      final signals = await MobileHardeningKit().screenEvents.take(1).toList();

      expect(signals, hasLength(1));
      expect(signals.single.type, HardeningSignalType.externalDisplay);
      expect(signals.single.metadata, <String, Object>{'connected': false});
    },
  );

  test('screenEvents reports unknown signal types as format errors', () async {
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
      MobileHardeningKit().screenEvents,
      emitsError(isA<FormatException>()),
    );
  });

  test('deprecated stream forwards to screenEvents', () async {
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(
        onListen: (arguments, events) => events.success(<String, Object?>{
          'type': 'screenshotTaken',
          'observedAt': '2026-01-02T03:04:05Z',
        }),
      ),
    );
    final kit = MobileHardeningKit();

    // ignore: deprecated_member_use_from_same_package
    final signals = await kit.stream.take(1).toList();

    expect(signals.single.type, HardeningSignalType.screenshotTaken);
    // ignore: deprecated_member_use_from_same_package
    expect(kit.stream, kit.screenEvents);
  });

  test('screenEvents listeners share one native subscription', () async {
    final native = mockNative(eventChannel);
    final kitA = MobileHardeningKit();
    final kitB = MobileHardeningKit();

    final first = kitA.screenEvents.listen((_) {});
    final second = kitB.screenEvents.listen((_) {});
    await pump();
    expect(native.listens, hasLength(1));

    await first.cancel();
    await pump();
    expect(native.cancels, 0);

    await second.cancel();
    await pump();
    expect(native.cancels, 1);

    final third = kitA.screenEvents.listen((_) {});
    await pump();
    expect(native.listens, hasLength(2));
    await third.cancel();
    await pump();
    expect(native.cancels, 2);
  });

  test(
    'cancelling one screenEvents listener keeps the other receiving',
    () async {
      late MockStreamHandlerEventSink sink;
      mockNative(eventChannel, onListen: (events) => sink = events);
      final kit = MobileHardeningKit();
      final received = <HardeningSignal>[];

      final first = kit.screenEvents.listen((_) {});
      final second = kit.screenEvents.listen(received.add);
      await pump();
      await first.cancel();
      sink.success(<String, Object?>{
        'type': 'externalDisplay',
        'observedAt': '2026-01-02T03:04:05Z',
      });
      await pump();

      expect(received.map((s) => s.type), <HardeningSignalType>[
        HardeningSignalType.externalDisplay,
      ]);
      await second.cancel();
    },
  );

  test(
    'IntegrityMonitorConfig defaults, clamping, equality, and hash code',
    () {
      const defaults = IntegrityMonitorConfig();

      expect(defaults.interval, const Duration(seconds: 30));
      expect(defaults.checkOnResume, isTrue);
      expect(defaults.toMap(), <String, Object?>{
        'intervalMs': 30000,
        'checkOnResume': true,
      });
      expect(
        const IntegrityMonitorConfig(
          interval: Duration(seconds: 1),
          checkOnResume: false,
        ).toMap(),
        <String, Object?>{'intervalMs': 5000, 'checkOnResume': false},
      );
      expect(
        const IntegrityMonitorConfig(interval: Duration(seconds: 5))
            .toMap()['intervalMs'],
        5000,
      );
      expect(defaults, const IntegrityMonitorConfig());
      expect(defaults.hashCode, const IntegrityMonitorConfig().hashCode);
      expect(defaults == Object(), isFalse);
      expect(
        defaults,
        isNot(const IntegrityMonitorConfig(interval: Duration(seconds: 31))),
      );
      expect(
        defaults,
        isNot(const IntegrityMonitorConfig(checkOnResume: false)),
      );
      expect(defaults.toString(), contains('checkOnResume: true'));
    },
  );

  test(
    'integrityEvents sends clamped config and omits a null certificate',
    () async {
      final native = mockNative(integrityChannel);

      final subscription =
          MobileHardeningKit(
                trustedAccessibilityPackages: const <String>{'com.b', 'com.a'},
              )
              .integrityEvents(
                const IntegrityMonitorConfig(
                  interval: Duration(seconds: 2),
                  checkOnResume: false,
                ),
              )
              .listen((_) {});
      await pump();

      expect(native.listens.single, <String, Object?>{
        'intervalMs': 5000,
        'checkOnResume': false,
        'trustedAccessibilityPackages': <String>['com.a', 'com.b'],
      });
      await subscription.cancel();
      await pump();
      expect(native.cancels, 1);
    },
  );

  test('integrityEvents sends the certificate and default config', () async {
    final native = mockNative(integrityChannel);

    final subscription = MobileHardeningKit(
      expectedSigningCertificateSha256: 'ab:cd',
    ).integrityEvents().listen((_) {});
    await pump();

    expect(native.listens.single, <String, Object?>{
      'intervalMs': 30000,
      'checkOnResume': true,
      'expectedSigningCertificateSha256': 'ab:cd',
      'trustedAccessibilityPackages': <String>[],
    });
    await subscription.cancel();
  });

  test(
    'integrityEvents shares one native subscription for the same config',
    () async {
      final native = mockNative(integrityChannel);
      const config = IntegrityMonitorConfig(interval: Duration(seconds: 10));
      final kitA = MobileHardeningKit(
        trustedAccessibilityPackages: const <String>{'a', 'b'},
      );
      final kitB = MobileHardeningKit(
        trustedAccessibilityPackages: const <String>{'b', 'a'},
      );

      final first = kitA.integrityEvents(config).listen((_) {});
      final second = kitB.integrityEvents(config).listen((_) {});
      await pump();
      expect(native.listens, hasLength(1));

      await first.cancel();
      await pump();
      expect(native.cancels, 0);
      await second.cancel();
      await pump();
      expect(native.cancels, 1);
    },
  );

  test('integrityEvents rejects a different config while active', () async {
    mockNative(integrityChannel);
    final kit = MobileHardeningKit();
    final subscription = kit.integrityEvents().listen((_) {});
    await pump();

    expect(
      () => kit.integrityEvents(
        const IntegrityMonitorConfig(interval: Duration(seconds: 10)),
      ),
      throwsStateError,
    );
    expect(
      () => kit.integrityEvents(
        const IntegrityMonitorConfig(checkOnResume: false),
      ),
      throwsStateError,
    );
    expect(
      () =>
          MobileHardeningKit(expectedSigningCertificateSha256: 'ab')
              .integrityEvents(),
      throwsStateError,
    );
    expect(
      () =>
          MobileHardeningKit(trustedAccessibilityPackages: const <String>{'x'})
              .integrityEvents(),
      throwsStateError,
    );

    await subscription.cancel();
  });

  test('a stream keeps the session of its own integrityEvents call', () async {
    final native = mockNative(integrityChannel);
    final withCertificate = MobileHardeningKit(
      expectedSigningCertificateSha256: 'ab:cd',
    ).integrityEvents();
    // Created before anyone listens: must not overwrite the session above.
    final withoutCertificate = MobileHardeningKit().integrityEvents();

    final first = withCertificate.listen((_) {});
    await pump();
    expect(
      native.listens.single,
      containsPair('expectedSigningCertificateSha256', 'ab:cd'),
    );

    final errors = <Object>[];
    var done = false;
    final second = withoutCertificate.listen(
      (_) {},
      onError: errors.add,
      onDone: () => done = true,
    );
    await pump();
    expect(errors.single, isA<StateError>());
    expect(done, isTrue);
    expect(native.listens, hasLength(1));

    // The failed subscription did not disturb the active session.
    await second.cancel();
    await pump();
    expect(native.cancels, 0);
    await first.cancel();
    await pump();
    expect(native.cancels, 1);
  });

  test('the first listener wins whichever stream was created first', () async {
    final native = mockNative(integrityChannel);
    final withCertificate = MobileHardeningKit(
      expectedSigningCertificateSha256: 'ab:cd',
    ).integrityEvents();
    final withoutCertificate = MobileHardeningKit().integrityEvents();

    final first = withoutCertificate.listen((_) {});
    await pump();
    expect(
      native.listens.single,
      isNot(contains('expectedSigningCertificateSha256')),
    );

    final errors = <Object>[];
    final second = withCertificate.listen((_) {}, onError: errors.add);
    await pump();
    expect(errors.single, isA<StateError>());

    // The same session joins the existing native subscription.
    final third = withoutCertificate.listen((_) {});
    await pump();
    expect(native.listens, hasLength(1));
    await first.cancel();
    await second.cancel();
    await third.cancel();
    await pump();
    expect(native.cancels, 1);

    // After the last listener leaves, the other session can start.
    final again = withCertificate.listen((_) {});
    await pump();
    expect(
      native.listens.last,
      containsPair('expectedSigningCertificateSha256', 'ab:cd'),
    );
    await again.cancel();
  });

  test('bound integrity streams forward events, errors, and done', () async {
    mockNative(
      integrityChannel,
      onListen: (events) {
        events.success(integrityEvent(<String, Object?>{'change': 'detected'}));
        events.error(code: 'boom', message: 'native failure');
        events.endOfStream();
      },
    );
    final received = <HardeningSignal>[];
    final errors = <Object>[];
    final stream = MobileHardeningKit().integrityEvents();
    final subscription = stream.listen(received.add, onError: errors.add);
    await pump();
    await pump();

    expect(received.single.type, HardeningSignalType.instrumentation);
    expect(errors.single, isA<PlatformException>());
    await subscription.cancel();
  });

  test('re-listening to a held integrity stream keeps its config', () async {
    final native = mockNative(integrityChannel);
    final stream = MobileHardeningKit().integrityEvents(
      const IntegrityMonitorConfig(interval: Duration(seconds: 45)),
    );
    await stream.listen((_) {}).cancel();
    await pump();

    final again = stream.listen((_) {});
    await pump();

    expect(native.listens, hasLength(2));
    expect((native.listens.last! as Map)['intervalMs'], 45000);
    await again.cancel();
  });

  test(
    'integrityEvents allows a new config after the last listener cancels',
    () async {
      final native = mockNative(integrityChannel);
      final kit = MobileHardeningKit();
      final first = kit.integrityEvents().listen((_) {});
      await pump();
      await first.cancel();
      await pump();

      final second = kit
          .integrityEvents(
            const IntegrityMonitorConfig(interval: Duration(seconds: 12)),
          )
          .listen((_) {});
      await pump();

      expect(native.listens, hasLength(2));
      expect((native.listens.last! as Map)['intervalMs'], 12000);
      await second.cancel();
    },
  );

  test(
    'integrityEvents decodes change, trigger, and techniques metadata',
    () async {
      mockNative(
        integrityChannel,
        onListen: (events) {
          events.success('ignored');
          events.success(
            integrityEvent(<String, Object?>{
              'change': 'detected',
              'trigger': 'start',
              'techniques': <String>['threadName', 'maps'],
              'artifacts': <String>['thread:gum-js-loop'],
            }),
          );
          events.success(
            integrityEvent(<String, Object?>{
              'change': 'cleared',
              'trigger': 'interval',
              'techniques': <String>['maps'],
            }),
          );
        },
      );

      final signals = await MobileHardeningKit()
          .integrityEvents()
          .take(2)
          .toList();

      expect(
        signals.map((s) => s.type),
        everyElement(HardeningSignalType.instrumentation),
      );
      expect(signals.first.metadata['change'], 'detected');
      expect(signals.first.metadata['trigger'], 'start');
      expect(signals.first.metadata['techniques'], <String>[
        'threadName',
        'maps',
      ]);
      expect(signals.last.metadata['change'], 'cleared');
      expect(signals.last.metadata['trigger'], 'interval');
    },
  );

  test('integrityEvents reports unknown types and platform errors', () async {
    mockNative(
      integrityChannel,
      onListen: (events) {
        events.success(<String, Object?>{
          'type': 'unknown',
          'observedAt': '2026-01-02T03:04:05Z',
        });
        events.error(code: 'monitor_failed');
      },
    );

    await expectLater(
      MobileHardeningKit().integrityEvents(),
      emitsInOrder(<Matcher>[
        emitsError(isA<FormatException>()),
        emitsError(isA<PlatformException>()),
      ]),
    );
  });

  test(
    'checkIntegrityNow invokes the native method without arguments',
    () async {
      MethodCall? received;
      messenger.setMockMethodCallHandler(channel, (call) async {
        received = call;
        return null;
      });

      await MobileHardeningKit().checkIntegrityNow();

      expect(received?.method, 'checkIntegrityNow');
      expect(received?.arguments, isNull);
    },
  );

  test('signal decoder applies safe defaults for missing optional fields', () {
    final signal = HardeningSignal.fromMap(<Object?, Object?>{
      'type': 'emulator',
    });

    expect(signal.type, HardeningSignalType.emulator);
    expect(
      signal.observedAt,
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    );
    expect(signal.metadata, isEmpty);
  });

  test('signal decoder defaults invalid timestamps and non-map metadata', () {
    final signal = HardeningSignal.fromMap(<Object?, Object?>{
      'type': 'emulator',
      'observedAt': 'not-a-timestamp',
      'metadata': <String>['not', 'a', 'map'],
    });

    expect(
      signal.observedAt,
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    );
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
    },
  );

  test('signal equality distinguishes type, timestamp, metadata, and other objects', () {
    final signal = HardeningSignal(
      type: HardeningSignalType.instrumentation,
      observedAt: DateTime.utc(2026),
      metadata: const <String, Object>{'artifact': 'frida'},
    );

    expect(signal == Object(), isFalse);
    expect(
      signal,
      isNot(
        HardeningSignal(
          type: HardeningSignalType.root,
          observedAt: DateTime.utc(2026),
          metadata: const <String, Object>{'artifact': 'frida'},
        ),
      ),
    );
    expect(
      signal,
      isNot(
        HardeningSignal(
          type: HardeningSignalType.instrumentation,
          observedAt: DateTime.utc(2026, 1, 2),
          metadata: const <String, Object>{'artifact': 'frida'},
        ),
      ),
    );
    expect(
      signal,
      isNot(
        HardeningSignal(
          type: HardeningSignalType.instrumentation,
          observedAt: DateTime.utc(2026),
          metadata: const <String, Object>{'artifact': 'xposed'},
        ),
      ),
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

  test(
    'setScreenProtection sends options and decodes the applied state',
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
    },
  );

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

    final state = await MobileHardeningKit().setScreenProtection(
      ScreenProtection.off,
    );

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

    expect(
      MobileHardeningKit().setScreenProtection(ScreenProtection.off),
      throwsFormatException,
    );
  });

  test('setScreenProtection propagates platform errors', () {
    messenger.setMockMethodCallHandler(
      channel,
      (call) async => throw PlatformException(code: 'unavailable'),
    );

    expect(
      MobileHardeningKit().setScreenProtection(ScreenProtection.off),
      throwsA(isA<PlatformException>()),
    );
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
        stateReply()..['unavailable'] = <Object?>[1],
      ),
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
      ),
    );
    expect(all.hashCode, all.hashCode);
    expect(all.hashCode, isNot(ScreenProtection.off.hashCode));
    expect(all == Object(), isFalse);
    expect(
      ScreenProtection.off,
      isNot(const ScreenProtection(blockCapture: true)),
    );
    expect(
      ScreenProtection.off,
      isNot(const ScreenProtection(obscureWhileCaptured: true)),
    );
    expect(
      ScreenProtection.off,
      isNot(const ScreenProtection(obscureAppSwitcher: true)),
    );
  });

  test('ScreenProtectionState equality and hash code', () {
    ScreenProtectionState make({
      bool blocked = true,
      bool whileCaptured = false,
      bool switcher = true,
      List<String> unavailable = const <String>['a:b'],
    }) => ScreenProtectionState(
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
