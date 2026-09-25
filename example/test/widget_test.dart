import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_hardening_kit_example/main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const methodChannel = MethodChannel('mobile_hardening_kit');
  const eventChannel = EventChannel('mobile_hardening_kit/events');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() {
    messenger.setMockMethodCallHandler(methodChannel, null);
    messenger.setMockStreamHandler(eventChannel, null);
  });

  testWidgets('sample displays raw snapshot and stream records',
      (tester) async {
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

  testWidgets('shows snapshot errors and recovers on a later scan',
      (tester) async {
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
        <String, Object?>{
          'type': 'root',
          'observedAt': '2026-01-02T03:04:05Z',
        },
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

  testWidgets('enabling protection is reflected and cleared on disposal',
      (tester) async {
    final protectionRequests = <bool>[];
    messenger.setMockMethodCallHandler(methodChannel, (call) async {
      if (call.method == 'setScreenProtectionEnabled') {
        final arguments = call.arguments as Map<Object?, Object?>;
        protectionRequests.add(arguments['enabled'] as bool);
        return null;
      }
      return <Object?>[];
    });
    messenger.setMockStreamHandler(
      eventChannel,
      MockStreamHandler.inline(onListen: (arguments, events) {}),
    );

    await tester.pumpWidget(const HardeningExampleApp());
    await tester.pumpAndSettle();
    await tester.tap(find.byType(SwitchListTile));
    await tester.pumpAndSettle();

    expect(tester.widget<SwitchListTile>(find.byType(SwitchListTile)).value,
        isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pumpAndSettle();

    expect(protectionRequests, <bool>[true, false]);
  });

  testWidgets('keeps protection disabled and reports platform errors',
      (tester) async {
    messenger.setMockMethodCallHandler(methodChannel, (call) async {
      if (call.method == 'setScreenProtectionEnabled') {
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
    await tester.tap(find.byType(SwitchListTile));
    await tester.pumpAndSettle();

    expect(tester.widget<SwitchListTile>(find.byType(SwitchListTile)).value,
        isFalse);
    expect(find.text('Signal collection failed'), findsOneWidget);
    expect(find.textContaining('protection_unavailable'), findsOneWidget);
  });

  testWidgets('does not update a disposed screen when a scan completes',
      (tester) async {
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
}
