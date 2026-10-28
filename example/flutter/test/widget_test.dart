import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit_example/main.dart';
import 'package:mobile_hardening_kit_example/play_sample_client.dart';

class _ScriptedPlaySampleClient extends PlaySampleClient {
  _ScriptedPlaySampleClient(this.responses)
    : super(backend: null, cloudProjectNumber: null);

  final List<Object> responses;
  final List<(bool, List<String>)> submittedKitSnapshots =
      <(bool, List<String>)>[];

  @override
  Future<Map<String, Object?>> check({
    required String policy,
    required bool kitAvailable,
    required List<String> kitSignals,
  }) async {
    submittedKitSnapshots.add((kitAvailable, List<String>.of(kitSignals)));
    final response = responses.removeAt(0);
    if (response is Exception) throw response;
    return response as Map<String, Object?>;
  }
}

Map<String, Object?> _verifiedAllow() => <String, Object?>{
  'verification': 'verified',
  'policy': 'or',
  'verdicts': <String, Object?>{
    'appRecognition': 'PLAY_RECOGNIZED',
    'appLicensing': 'LICENSED',
    'deviceRecognition': <String>['MEETS_DEVICE_INTEGRITY'],
  },
  'risk': <String, String>{
    'kit': 'unavailable',
    'provider': 'notDetected',
    'combined': 'notDetected',
  },
  'decision': 'allow',
  'reasons': <String>[],
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const methodChannel = MethodChannel('mobile_hardening_kit');
  const playChannel = MethodChannel(
    'mobile_hardening_kit_example/play_integrity',
  );
  const eventChannel = EventChannel('mobile_hardening_kit/events');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() {
    messenger.setMockMethodCallHandler(methodChannel, null);
    messenger.setMockMethodCallHandler(playChannel, null);
    messenger.setMockStreamHandler(eventChannel, null);
  });

  testWidgets('sample displays raw snapshot and stream records', (
    tester,
  ) async {
    messenger.setMockMethodCallHandler(
      methodChannel,
      (call) async => <Object?>[
        <String, Object?>{
          'type': 'instrumentation',
          'observedAt': '2026-01-02T03:04:05.000Z',
          'metadata': <String, Object?>{
            'artifacts': <String>['frida'],
            'tracerPort': 27042,
          },
        },
      ],
    );
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(
        onListen: (arguments, events) {
          events.success(<String, Object?>{
            'type': 'screenCaptureActive',
            'observedAt': '2026-01-02T03:04:06.000Z',
            'metadata': <String, Object?>{'active': true},
          });
          events.success(<String, Object?>{
            'type': 'screenCaptureActive',
            'observedAt': '2026-01-02T03:04:07.000Z',
            'metadata': <String, Object?>{'active': false},
          });
        },
      ),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpAndSettle();

    expect(find.text('Snapshot response (raw JSON)'), findsOneWidget);
    expect(find.text('Event stream (raw JSON)'), findsOneWidget);
    final snapshotJson = tester
        .widget<SelectableText>(
          find.byKey(const ValueKey<String>('snapshot-signals-json')),
        )
        .data!;
    expect(snapshotJson, contains('"type": "instrumentation"'));
    expect(snapshotJson, contains('"artifacts": ['));
    expect(snapshotJson, isNot(contains('"confidence"')));

    final streamJson = tester
        .widget<SelectableText>(
          find.byKey(const ValueKey<String>('stream-signals-json')),
        )
        .data!;
    expect(streamJson, contains('"type": "screenCaptureActive"'));
    expect(
      streamJson.indexOf('"active": true'),
      lessThan(streamJson.indexOf('"active": false')),
    );
    expect(streamJson, isNot(contains('"confidence"')));
  });
  testWidgets('shows loading until the snapshot finishes', (tester) async {
    final pendingSnapshot = Completer<Object?>();
    messenger.setMockMethodCallHandler(
      methodChannel,
      (call) => pendingSnapshot.future,
    );
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());

    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    final scanButtonFinder = find.ancestor(
      of: find.text('Scan now'),
      matching: find.byWidgetPredicate((widget) => widget is ButtonStyleButton),
    );
    final scanButton = tester.widget<ButtonStyleButton>(scanButtonFinder);
    expect(scanButton.onPressed, isNull);

    pendingSnapshot.complete(<Object?>[
      <String, Object?>{
        'type': 'emulator',
        'observedAt': '2026-01-02T03:04:05Z',
        'metadata': <String, Object?>{'indicatorCount': 2},
      },
    ]);
    await tester.pumpAndSettle();

    expect(find.byType(LinearProgressIndicator), findsNothing);
    expect(
      tester.widget<ButtonStyleButton>(scanButtonFinder).onPressed,
      isNotNull,
    );
    final snapshotJson = tester
        .widget<SelectableText>(
          find.byKey(const ValueKey<String>('snapshot-signals-json')),
        )
        .data!;
    expect(snapshotJson, contains('"type": "emulator"'));
  });

  testWidgets('shows snapshot errors and recovers on a later scan', (
    tester,
  ) async {
    var failFirstScan = true;
    messenger.setMockMethodCallHandler(methodChannel, (call) async {
      if (failFirstScan) {
        failFirstScan = false;
        throw PlatformException(
          code: 'scan_failed',
          message: 'snapshot unavailable',
        );
      }
      return <Object?>[
        <String, Object?>{'type': 'root', 'observedAt': '2026-01-02T03:04:05Z'},
      ];
    });
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpAndSettle();

    expect(find.text('Signal collection failed'), findsOneWidget);
    expect(find.textContaining('snapshot unavailable'), findsOneWidget);

    await tester.tap(find.text('Scan now'));
    await tester.pumpAndSettle();

    expect(find.text('Signal collection failed'), findsNothing);
    final snapshotJson = tester
        .widget<SelectableText>(
          find.byKey(const ValueKey<String>('snapshot-signals-json')),
        )
        .data!;
    expect(snapshotJson, contains('"type": "root"'));
  });

  testWidgets('shows errors delivered by the event stream', (tester) async {
    final pendingSnapshot = Completer<Object?>();
    messenger.setMockMethodCallHandler(
      methodChannel,
      (call) => pendingSnapshot.future,
    );
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(
        onListen: (arguments, events) {
          events.error(
            code: 'stream_disconnected',
            message: 'event source unavailable',
          );
        },
      ),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pump();

    expect(find.text('Signal collection failed'), findsOneWidget);
    expect(find.textContaining('stream_disconnected'), findsOneWidget);

    pendingSnapshot.complete(<Object?>[]);
    await tester.pumpAndSettle();
    expect(find.text('Signal collection failed'), findsOneWidget);
  });

  testWidgets('enabling protection is reflected and cleared on disposal', (
    tester,
  ) async {
    final protectionRequests = <Map<Object?, Object?>>[];
    messenger.setMockMethodCallHandler(methodChannel, (call) async {
      if (call.method == 'setScreenProtection') {
        final arguments = call.arguments as Map<Object?, Object?>;
        protectionRequests.add(arguments);
        return <String, Object?>{
          'captureBlocked': arguments['blockCapture'],
          'obscuresWhileCaptured': false,
          'obscuresAppSwitcher': arguments['obscureAppSwitcher'],
          'unavailable': arguments['blockCapture'] == true
              ? <Object?>['obscureWhileCaptured:apiLevel']
              : <Object?>[],
        };
      }
      return <Object?>[];
    });
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey<String>('protection-toggle')));
    await tester.pumpAndSettle();

    expect(
      tester
          .widget<SwitchListTile>(
            find.byKey(const ValueKey<String>('protection-toggle')),
          )
          .value,
      isTrue,
    );
    expect(
      find.textContaining('obscureWhileCaptured:apiLevel'),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();

    expect(protectionRequests, <Map<Object?, Object?>>[
      <String, Object?>{
        'blockCapture': true,
        'obscureWhileCaptured': true,
        'obscureAppSwitcher': true,
      },
      <String, Object?>{
        'blockCapture': false,
        'obscureWhileCaptured': false,
        'obscureAppSwitcher': false,
      },
    ]);
  });

  testWidgets('keeps protection disabled and reports platform errors', (
    tester,
  ) async {
    messenger.setMockMethodCallHandler(methodChannel, (call) async {
      if (call.method == 'setScreenProtection') {
        throw PlatformException(
          code: 'protection_unavailable',
          message: 'window unavailable',
        );
      }
      return <Object?>[];
    });
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey<String>('protection-toggle')));
    await tester.pumpAndSettle();

    expect(
      tester
          .widget<SwitchListTile>(
            find.byKey(const ValueKey<String>('protection-toggle')),
          )
          .value,
      isFalse,
    );
    expect(find.text('Signal collection failed'), findsOneWidget);
    expect(find.textContaining('protection_unavailable'), findsOneWidget);
  });

  testWidgets('does not update a disposed screen when a scan completes', (
    tester,
  ) async {
    final pendingSnapshot = Completer<Object?>();
    messenger.setMockMethodCallHandler(
      methodChannel,
      (call) => pendingSnapshot.future,
    );
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpWidget(const SizedBox.shrink());
    pendingSnapshot.complete(<Object?>[]);
    await tester.pump();

    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'sample check explains unconfigured state without affecting kit',
    (tester) async {
      messenger.setMockMethodCallHandler(
        methodChannel,
        (call) async => <Object?>[],
      );
      messenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(onListen: (arguments, events) {}),
      );
      await tester.pumpWidget(const HardeningExampleApp());
      await tester.pumpAndSettle();

      final checkButton = find.byKey(const ValueKey<String>('check-sample'));
      await tester.scrollUntilVisible(
        checkButton,
        400,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.tap(checkButton);
      await tester.pumpAndSettle();

      expect(find.text('Sample check unavailable'), findsOneWidget);
      expect(find.byKey(const ValueKey<String>('sample-result')), findsNothing);
    },
  );

  test('response parser rejects unknown verdicts and binding separates availability', () {
    final unknownVerdict = _verifiedAllow()
      ..['verdicts'] = <String, Object?>{
        'appRecognition': 'UNRECOGNIZED_ACCOUNT',
        'appLicensing': 'LICENSED',
        'deviceRecognition': <String>['MEETS_DEVICE_INTEGRITY'],
      };
    expect(
      () =>
          PlaySampleClient.parseResponse(200, jsonEncode(unknownVerdict), 'or'),
      throwsA(isA<PlaySampleException>()),
    );
    expect(
      PlaySampleClient.canonical(
        requestId: 'a' * 32,
        policy: 'or',
        kitAvailable: false,
        kitSignals: const <String>[],
      ),
      isNot(
        PlaySampleClient.canonical(
          requestId: 'a' * 32,
          policy: 'or',
          kitAvailable: true,
          kitSignals: const <String>[],
        ),
      ),
    );
  });

  testWidgets(
    'later provider error clears allow and submits unknown snapshot',
    (tester) async {
      var snapshotCalls = 0;
      messenger.setMockMethodCallHandler(methodChannel, (call) async {
        snapshotCalls++;
        if (snapshotCalls == 3) {
          throw PlatformException(code: 'snapshot_error');
        }
        return <Object?>[
          <String, Object?>{
            'type': 'externalDisplay',
            'observedAt': '2026-10-13T00:00:00Z',
            'metadata': <String, Object?>{},
          },
        ];
      });
      messenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(onListen: (arguments, events) {}),
      );
      final client = _ScriptedPlaySampleClient(<Object>[
        _verifiedAllow(),
        const PlaySampleException('Provider unavailable'),
      ]);
      await tester.pumpWidget(
        MaterialApp(home: SignalExplorerPage(sampleClient: client)),
      );
      await tester.pumpAndSettle();
      final checkButton = find.byKey(const ValueKey<String>('check-sample'));
      await tester.scrollUntilVisible(
        checkButton,
        400,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.tap(checkButton);
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey<String>('sample-result')),
        findsOneWidget,
      );

      await tester.tap(checkButton);
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey<String>('sample-result')), findsNothing);
      expect(client.submittedKitSnapshots[0].$1, isTrue);
      expect(client.submittedKitSnapshots[0].$2, <String>['externalDisplay']);
      expect(client.submittedKitSnapshots[1].$1, isFalse);
      expect(client.submittedKitSnapshots[1].$2, isEmpty);
    },
  );

  group('integrity monitor section', () {
    const integrityChannel = EventChannel(
      'mobile_hardening_kit/integrity_events',
    );
    const toggleKey = ValueKey<String>('integrity-monitor-toggle');
    const checkNowKey = ValueKey<String>('integrity-check-now');

    late List<MethodCall> calls;
    late List<Object?> listenArguments;
    late int cancels;
    MockStreamHandlerEventSink? sink;

    Map<String, Object?> event(
      String type,
      String change,
      String trigger, {
      List<String> techniques = const <String>[],
      List<String> artifacts = const <String>[],
      String observedAt = '2026-01-02T03:04:05.123Z',
    }) => <String, Object?>{
      'type': type,
      'observedAt': observedAt,
      'metadata': <String, Object?>{
        'change': change,
        'trigger': trigger,
        'techniques': techniques,
        'artifacts': artifacts,
      },
    };

    setUp(() {
      calls = <MethodCall>[];
      listenArguments = <Object?>[];
      cancels = 0;
      sink = null;
      messenger.setMockMethodCallHandler(methodChannel, (call) async {
        calls.add(call);
        return call.method == 'snapshot' ? <Object?>[] : null;
      });
      messenger.setMockStreamHandler(
        eventChannel,
        MockStreamHandler.inline(onListen: (arguments, events) {}),
      );
      messenger.setMockStreamHandler(
        integrityChannel,
        MockStreamHandler.inline(
          onListen: (arguments, events) {
            listenArguments.add(arguments);
            sink = events;
            events.success(
              event(
                'instrumentation',
                'detected',
                'start',
                techniques: <String>['maps', 'threadName'],
                artifacts: <String>['/data/frida-agent.so'],
              ),
            );
          },
          onCancel: (arguments) => cancels++,
        ),
      );
    });

    tearDown(() {
      messenger.setMockStreamHandler(integrityChannel, null);
    });

    // Event-channel messages take several async hops, with no frame in between.
    Future<void> settle(WidgetTester tester) async {
      await tester.pumpAndSettle();
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 20)),
      );
      await tester.pumpAndSettle();
    }

    Future<void> pumpApp(WidgetTester tester) async {
      await tester.binding.setSurfaceSize(const Size(800, 4000));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(const HardeningExampleApp());
      await settle(tester);
    }

    String text(WidgetTester tester, String key) =>
        tester.widget<Text>(find.byKey(ValueKey<String>(key))).data!;

    testWidgets('starts stopped with a disabled check-now button', (
      tester,
    ) async {
      await pumpApp(tester);

      expect(tester.widget<SwitchListTile>(find.byKey(toggleKey)).value, false);
      expect(
        tester.widget<ButtonStyleButton>(find.byKey(checkNowKey)).onPressed,
        isNull,
      );
      expect(
        find.byKey(const ValueKey<String>('integrity-events-empty')),
        findsOneWidget,
      );
      expect(text(tester, 'integrity-events-count'), 'Integrity events: 0');
      expect(listenArguments, isEmpty);
    });

    testWidgets('toggle subscribes and lists the event fields', (tester) async {
      await pumpApp(tester);

      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      expect(listenArguments, hasLength(1));
      final arguments = listenArguments.single! as Map<Object?, Object?>;
      expect(arguments['intervalMs'], 30000);
      expect(arguments['checkOnResume'], true);
      expect(tester.widget<SwitchListTile>(find.byKey(toggleKey)).value, true);
      expect(text(tester, 'integrity-events-count'), 'Integrity events: 1');
      expect(
        find.byKey(const ValueKey<String>('integrity-events-empty')),
        findsNothing,
      );
      expect(
        text(tester, 'integrity-event-0-title'),
        'instrumentation · detected',
      );
      expect(text(tester, 'integrity-event-0-type'), 'type: instrumentation');
      expect(text(tester, 'integrity-event-0-change'), 'change: detected');
      expect(text(tester, 'integrity-event-0-trigger'), 'trigger: start');
      expect(
        text(tester, 'integrity-event-0-techniques'),
        'techniques: maps, threadName',
      );
      expect(
        text(tester, 'integrity-event-0-artifacts'),
        'artifacts: /data/frida-agent.so',
      );
      expect(
        text(tester, 'integrity-event-0-observedAt'),
        'observedAt: 2026-01-02T03:04:05.123Z',
      );
    });

    testWidgets('lists newest first and shows dashes for empty lists', (
      tester,
    ) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      sink!.success(event('root', 'cleared', 'manual'));
      await settle(tester);

      expect(text(tester, 'integrity-event-1-title'), 'root · cleared');
      expect(text(tester, 'integrity-event-1-techniques'), 'techniques: -');
      expect(text(tester, 'integrity-event-1-artifacts'), 'artifacts: -');
      final newest = tester.getTopLeft(
        find.byKey(const ValueKey<String>('integrity-event-1')),
      );
      final oldest = tester.getTopLeft(
        find.byKey(const ValueKey<String>('integrity-event-0')),
      );
      expect(newest.dy, lessThan(oldest.dy));
    });

    testWidgets('missing metadata renders dashes', (tester) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      sink!.success(<String, Object?>{
        'type': 'emulator',
        'observedAt': '2026-01-02T03:04:05Z',
      });
      await settle(tester);

      expect(text(tester, 'integrity-event-1-title'), 'emulator · -');
      expect(text(tester, 'integrity-event-1-trigger'), 'trigger: -');
    });

    testWidgets('the selected interval is sent and locked while running', (
      tester,
    ) async {
      await pumpApp(tester);
      await tester.tap(
        find.byKey(const ValueKey<String>('integrity-interval-selector')),
      );
      await settle(tester);
      await tester.tap(find.text('5 s').last);
      await settle(tester);

      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      expect(
        (listenArguments.single! as Map<Object?, Object?>)['intervalMs'],
        5000,
      );
      expect(find.text('Running every 5 s'), findsOneWidget);
      final selector = tester.widget<DropdownButtonFormField<int>>(
        find.byKey(const ValueKey<String>('integrity-interval-selector')),
      );
      expect(selector.onChanged, isNull);
    });

    testWidgets('check now calls the method only while monitoring', (
      tester,
    ) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      await tester.tap(find.byKey(checkNowKey));
      await settle(tester);

      expect(calls.where((c) => c.method == 'checkIntegrityNow'), hasLength(1));
      expect(
        find.byKey(const ValueKey<String>('integrity-error')),
        findsNothing,
      );
    });

    testWidgets('check now failures are shown', (tester) async {
      messenger.setMockMethodCallHandler(methodChannel, (call) async {
        if (call.method == 'checkIntegrityNow') {
          throw PlatformException(code: 'check_failed', message: 'no monitor');
        }
        return <Object?>[];
      });
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      await tester.tap(find.byKey(checkNowKey));
      await settle(tester);

      expect(
        find.byKey(const ValueKey<String>('integrity-error')),
        findsOneWidget,
      );
      expect(find.textContaining('check_failed'), findsOneWidget);
    });

    testWidgets('stream errors are shown and cleared on restart', (
      tester,
    ) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      sink!.error(code: 'monitor_failed', message: 'native monitor stopped');
      await settle(tester);
      expect(find.textContaining('monitor_failed'), findsOneWidget);

      await tester.tap(find.byKey(toggleKey));
      await settle(tester);
      expect(
        find.byKey(const ValueKey<String>('integrity-error')),
        findsNothing,
      );
    });

    testWidgets(
      'toggling off cancels the subscription and disables check now',
      (tester) async {
        await pumpApp(tester);
        await tester.tap(find.byKey(toggleKey));
        await settle(tester);

        await tester.tap(find.byKey(toggleKey));
        await settle(tester);

        expect(cancels, 1);
        expect(
          tester.widget<SwitchListTile>(find.byKey(toggleKey)).value,
          false,
        );
        expect(
          tester.widget<ButtonStyleButton>(find.byKey(checkNowKey)).onPressed,
          isNull,
        );
        expect(text(tester, 'integrity-events-count'), 'Integrity events: 1');
      },
    );

    testWidgets('clear empties the list', (tester) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      await tester.tap(
        find.byKey(const ValueKey<String>('integrity-events-clear')),
      );
      await settle(tester);

      expect(text(tester, 'integrity-events-count'), 'Integrity events: 0');
      expect(
        find.byKey(const ValueKey<String>('integrity-events-empty')),
        findsOneWidget,
      );
    });

    testWidgets('keeps only the latest 50 events', (tester) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      for (var i = 0; i < 55; i++) {
        sink!.success(event('root', 'changed', 'interval'));
      }
      await settle(tester);

      expect(text(tester, 'integrity-events-count'), 'Integrity events: 50');
    });

    testWidgets('disposing the page cancels a running monitor', (tester) async {
      await pumpApp(tester);
      await tester.tap(find.byKey(toggleKey));
      await settle(tester);

      await tester.pumpWidget(const SizedBox());
      await settle(tester);

      expect(cancels, 1);
    });
  });
}
