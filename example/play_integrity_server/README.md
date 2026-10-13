# Play Integrity sample verification backend

This Go service implements the sample app's `POST /check` and `GET /health` endpoints. It decodes real Google Play Integrity tokens with server-side Application Default Credentials (ADC). It is not production authorization, user/tenant authentication, replay protection, or a trusted verdict for client-supplied kit signals. Decisions are illustrative sample actions only.

## Requirements and configuration

- Go 1.24 or newer; `golang.org/x/oauth2` is pinned to v0.30.0.
- A Google Cloud project linked to the Play app, Play Integrity API enabled, and a service identity authorized to decode tokens.
- `PLAY_INTEGRITY_PACKAGE_NAME` (optional; defaults to `com.mekari.mobile_hardening_kit_example`), matching the Android app package.
- `LISTEN_ADDR` (optional; defaults to `127.0.0.1:8080`). Use a private interface behind a TLS reverse proxy in deployment.
- ADC available to the server process. Set `GOOGLE_APPLICATION_CREDENTIALS` to a securely provisioned credential file, or use the runtime's supported workload identity/ADC mechanism. Credentials belong only on the backend; never place them in the Flutter app, repository, or logs.

## Provision Play Integrity

Enable the Google Play Integrity API in the cloud project linked to the app. Create a dedicated service identity and grant the minimum Play Console/API permissions needed to decode tokens for that app. Configure ADC for that identity in the backend runtime and verify its access before exposing the service. Keep service-account keys out of source control; prefer workload identity where available. The app must be correctly linked in Play Console and installed through an eligible Play testing track/account for useful app and licensing verdicts. Google may return unevaluated verdict categories depending on app distribution and device conditions.

Follow Google's [setup requirements](https://developer.android.com/google/play/integrity/setup) and [standard-request/server-verification flow](https://developer.android.com/google/play/integrity/standard) when provisioning the real integration.

## Run locally

```sh
cd example/play_integrity_server
go mod download
go run .
```

The process starts without credentials so health monitoring remains available. `GET http://127.0.0.1:8080/health` reports only HTTP service readiness; it does not check ADC or claim Google availability. A valid `/check` with absent or invalid ADC fails explicitly with a 503 credential error. An Android emulator can reach local development service at `http://10.0.2.2:8080`; keep it loopback/private and do not expose it over an untrusted network.

## Deploy

Run as a restricted, non-root identity with ADC/workload identity, outbound HTTPS access to `playintegrity.googleapis.com`, and no public direct listener. Terminate TLS at a trusted reverse proxy/load balancer, restrict inbound access as appropriate, and bind `LISTEN_ADDR` to a private interface. Configure Flutter with the HTTPS backend base URL and the exact package name. Health checks use `/health`; they intentionally do not prove credentials or Google's service are available.

## Request and decision behavior

`POST /check` accepts the sample wire contract: action `sample-check`, a fresh 32-character lowercase hex request id, one of `or`, `and`, `kitPrecedence`, or `providerPrecedence`, a snapshot-only kit signal list, and the opaque integrity token. The server reconstructs the canonical binding from these validated fields, computes its SHA-256 base64url request hash, and compares it with Google's decoded `requestDetails.requestHash`; the client does not submit a separate hash. It checks request package and token freshness (120 seconds old maximum, 30 seconds future tolerance) before using verdicts. Malformed input returns 400, binding/freshness/package mismatch returns 401, credential unavailability returns 503, and Google/upstream failures return 502. Error bodies never include the token, credential details, raw upstream body, or stack trace. The service does not blindly retry token decoding.

Kit findings are client-originated hints. Binding them does not authenticate their truth. Kit and provider risk remain separate; the selected policy combines available source results only. App recognition and licensing are independent baseline gates, not overridden by the risk reducer. Failed baselines yield `restrict`; unevaluated baselines yield `review`; environment risk produces illustrative `review`/`allow` outcomes. This is not a security boundary or production access-control policy.

The environment assessment uses local root/jailbreak, instrumentation, debugger, emulator, and developer/ADB findings as positive kit hints. An empty snapshot or failed scan contributes `unavailable`, never a negative. A verified, present `deviceIntegrity` section without `MEETS_DEVICE_INTEGRITY` contributes `detected`; a missing section contributes `unavailable`. A failed device tier is not a root diagnosis.

- `or` (default): a concern from any available source produces a combined concern.
- `and`: all available sources must report a concern. With one available source, that source's result is used; two sources are not required.
- `kitPrecedence` / `providerPrecedence`: use the preferred available source, falling back to the other.
- No available sources produce an unavailable assessment and a `review` decision.

For example, with app recognition and licensing both passing, a local emulator finding plus a passing Play device tier produces `review` under OR or kit precedence, but `allow` under AND or provider precedence. The original finding remains visible: the policy changes the interpretation, not the evidence.

## Verification

Behavior tests use injected decoded Google-envelope responses/errors; they do not create a fake runtime mode and make no live Google success claim. Run `go test ./...` and `go vet ./...` from this directory after configuring Go. Real successful decode additionally requires Google project/API and Play Console linkage/permissions, ADC, an eligible Play-distributed build, and a compatible test account/device.
