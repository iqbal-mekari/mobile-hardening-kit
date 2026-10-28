import 'dart:async';

import 'package:flutter/services.dart';

import 'hardening_signal.dart';

/// One native subscription to an [EventChannel], fanned out to any number of
/// Dart listeners.
///
/// The native stream is subscribed when the first listener attaches and
/// cancelled when the last one leaves, so cancelling one listener never stops
/// another. Non-map events are skipped; undecodable events surface as stream
/// errors (for example [FormatException] for unknown signal types).
class SharedEventStream {
  SharedEventStream(this._channel, {Object? Function()? arguments})
      : _arguments = arguments {
    _controller = StreamController<HardeningSignal>.broadcast(
      onListen: _subscribe,
      onCancel: _unsubscribe,
    );
  }

  final EventChannel _channel;
  final Object? Function()? _arguments;
  late final StreamController<HardeningSignal> _controller;
  StreamSubscription<Object?>? _subscription;

  /// The shared broadcast stream.
  Stream<HardeningSignal> get stream => _controller.stream;

  /// Whether at least one Dart listener is attached.
  bool get hasListeners => _controller.hasListener;

  void _subscribe() {
    _subscription = _channel.receiveBroadcastStream(_arguments?.call()).listen(
          _onEvent,
          onError: _controller.addError,
        );
  }

  Future<void> _unsubscribe() async {
    final subscription = _subscription;
    _subscription = null;
    await subscription?.cancel();
  }

  void _onEvent(Object? event) {
    if (event is! Map) return;
    try {
      _controller.add(HardeningSignal.fromMap(event));
    } catch (error, stackTrace) {
      _controller.addError(error, stackTrace);
    }
  }
}
