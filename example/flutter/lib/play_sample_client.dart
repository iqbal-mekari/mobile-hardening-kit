import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';

const _playChannel = MethodChannel(
  'mobile_hardening_kit_example/play_integrity',
);

class PlaySampleException implements Exception {
  const PlaySampleException(this.message);

  final String message;

  @override
  String toString() => message;
}

class PlaySampleClient {
  PlaySampleClient({required this.backend, required this.cloudProjectNumber});

  final Uri? backend;
  final int? cloudProjectNumber;

  static String requestId([Random? random]) {
    final source = random ?? Random.secure();
    return List<String>.generate(
      32,
      (_) => source.nextInt(16).toRadixString(16),
    ).join();
  }

  static String canonical({
    required String requestId,
    required String policy,
    required bool kitAvailable,
    required List<String> kitSignals,
  }) =>
      'mhk-sample-v1\nsample-check\n$requestId\n$policy\n${kitAvailable ? 'available' : 'unavailable'}\n${kitSignals.join(',')}';

  Future<Map<String, Object?>> check({
    required String policy,
    required bool kitAvailable,
    required List<String> kitSignals,
  }) async {
    final projectNumber = cloudProjectNumber;
    final base = backend;
    if (projectNumber == null || base == null) {
      throw const PlaySampleException(
        'Configure PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER and PLAY_INTEGRITY_BACKEND_URL to run a sample check.',
      );
    }
    final request = requestId();
    final binding = canonical(
      requestId: request,
      policy: policy,
      kitAvailable: kitAvailable,
      kitSignals: kitSignals,
    );
    final http = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      final tokenResult = await _playChannel
          .invokeMapMethod<Object?, Object?>('requestToken', <String, Object?>{
            'cloudProjectNumber': projectNumber,
            'requestPayload': binding,
          })
          .timeout(const Duration(seconds: 60));
      final token = tokenResult?['token'];
      if (token is! String || token.isEmpty) {
        throw const PlaySampleException(
          'Play Integrity did not return a token.',
        );
      }
      final req = await http
          .postUrl(base.resolve('/check'))
          .timeout(const Duration(seconds: 15));
      req.headers.contentType = ContentType.json;
      req.write(
        jsonEncode(<String, Object?>{
          'action': 'sample-check',
          'requestId': request,
          'policy': policy,
          'kitAvailable': kitAvailable,
          'kitSignals': kitSignals,
          'integrityToken': token,
        }),
      );
      final response = await req.close().timeout(const Duration(seconds: 20));
      final bytes = await response
          .fold<List<int>>(<int>[], (all, chunk) {
            if (all.length + chunk.length > 65536) {
              throw const PlaySampleException(
                'Backend response exceeded the 64 KB limit.',
              );
            }
            return all..addAll(chunk);
          })
          .timeout(const Duration(seconds: 10));
      return parseResponse(response.statusCode, utf8.decode(bytes), policy);
    } on PlatformException catch (error) {
      final message = error.message;
      throw PlaySampleException(
        message != null && message.isNotEmpty
            ? message.substring(0, min(240, message.length))
            : 'Play Integrity provider error (${error.code}).',
      );
    } on TimeoutException {
      throw const PlaySampleException('Play Integrity check timed out.');
    } on FormatException {
      throw const PlaySampleException('Backend returned malformed JSON.');
    } on SocketException {
      throw const PlaySampleException('Could not reach the sample backend.');
    } finally {
      http.close(force: true);
    }
  }

  static Map<String, Object?> parseResponse(
    int statusCode,
    String body,
    String policy,
  ) {
    final decoded = jsonDecode(body);
    if (decoded is! Map<String, dynamic>) {
      throw const PlaySampleException('Backend returned an invalid response.');
    }
    if (statusCode < 200 || statusCode >= 300) {
      final error = decoded['error'];
      final message = error is Map ? error['message'] : null;
      throw PlaySampleException(
        message is String && message.length <= 240
            ? message
            : 'Backend check failed (HTTP $statusCode).',
      );
    }
    final verdicts = decoded['verdicts'];
    final risk = decoded['risk'];
    const appRecognitionValues = <String>{
      'PLAY_RECOGNIZED',
      'UNRECOGNIZED_VERSION',
    };
    const appLicensingValues = <String>{'LICENSED', 'UNLICENSED'};
    const deviceValues = <String>{
      'MEETS_DEVICE_INTEGRITY',
      'MEETS_BASIC_INTEGRITY',
      'MEETS_STRONG_INTEGRITY',
      'MEETS_VIRTUAL_INTEGRITY',
    };
    const riskValues = <String>{'detected', 'notDetected', 'unavailable'};
    const decisionValues = <String>{'allow', 'review', 'restrict'};
    final device = verdicts is Map ? verdicts['deviceRecognition'] : null;
    final reasons = decoded['reasons'];
    if (statusCode != 200 ||
        decoded['verification'] != 'verified' ||
        !decisionValues.contains(decoded['decision']) ||
        decoded['policy'] != policy ||
        verdicts is! Map ||
        risk is! Map ||
        (verdicts['appRecognition'] != null &&
            !appRecognitionValues.contains(verdicts['appRecognition'])) ||
        (verdicts['appLicensing'] != null &&
            !appLicensingValues.contains(verdicts['appLicensing'])) ||
        (device != null &&
            (device is! List ||
                device.any(
                  (label) =>
                      label is! String ||
                      label.length > 80 ||
                      !deviceValues.contains(label),
                ))) ||
        !riskValues.contains(risk['kit']) ||
        !riskValues.contains(risk['provider']) ||
        !riskValues.contains(risk['combined']) ||
        reasons is! List ||
        reasons.length > 32 ||
        reasons.any((reason) => reason is! String || reason.length > 500)) {
      throw const PlaySampleException(
        'Backend returned an incomplete or unknown verification result.',
      );
    }
    return decoded;
  }
}
