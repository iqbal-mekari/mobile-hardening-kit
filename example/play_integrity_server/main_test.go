package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestReducePoliciesAndUnavailableSources(t *testing.T) {
	cases := []struct{ policy, kit, provider, want string }{
		{"or", "unavailable", "notDetected", "notDetected"}, {"or", "detected", "notDetected", "detected"},
		{"and", "notDetected", "notDetected", "notDetected"}, {"and", "detected", "notDetected", "notDetected"},
		{"and", "notDetected", "detected", "notDetected"}, {"and", "detected", "detected", "detected"},
		{"and", "unavailable", "detected", "detected"}, {"kitPrecedence", "notDetected", "detected", "notDetected"},
		{"kitPrecedence", "unavailable", "detected", "detected"}, {"providerPrecedence", "detected", "unavailable", "detected"},
		{"or", "unavailable", "unavailable", "unavailable"},
	}
	for _, c := range cases {
		if got := reduce(c.policy, c.kit, c.provider); got != c.want {
			t.Errorf("reduce(%s,%s,%s)=%s want %s", c.policy, c.kit, c.provider, got, c.want)
		}
	}
}

func TestCheckRejectsBoundInvalidVerdicts(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	req := validRequest()
	cases := []struct {
		name, want string
		mutate     func(*payload)
	}{
		{"hash", "Google request hash does not match", func(p *payload) { p.RequestDetails.RequestHash = "wrong" }},
		{"package", "Request package does not match configured package", func(p *payload) { p.RequestDetails.RequestPackageName = "wrong.package" }},
		{"stale", "Integrity token is outside the accepted time window", func(p *payload) { p.RequestDetails.TimestampMillis = formatMillis(now.Add(-maxAge - time.Second)) }},
		{"future", "Integrity token is outside the accepted time window", func(p *payload) {
			p.RequestDetails.TimestampMillis = formatMillis(now.Add(futureTolerance + time.Second))
		}},
		{"timestamp", "Integrity token timestamp is invalid", func(p *payload) { p.RequestDetails.TimestampMillis = "nope" }},
		{"app verdict", "App recognition verdict is unknown", func(p *payload) { p.AppIntegrity.AppRecognitionVerdict = "SOMETHING" }},
		{"recognized package missing", "Recognized app package is missing", func(p *payload) { p.AppIntegrity.PackageName = "" }},
		{"evaluated app package mismatch", "App package does not match configured package", func(p *payload) {
			p.AppIntegrity.AppRecognitionVerdict = "UNRECOGNIZED_VERSION"
			p.AppIntegrity.PackageName = "wrong.package"
		}},
		{"device label", "Device recognition verdict contains an unknown label", func(p *payload) { p.DeviceIntegrity.DeviceRecognitionVerdict = []string{"FAKE"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := goodPayload("com.test.app", now, reqHash(req))
			c.mutate(p)
			h := handler{packageName: "com.test.app", now: func() time.Time { return now }, decode: func(context.Context, string) (*decoded, error) { return &decoded{TokenPayloadExternal: p}, nil }}
			rr := serve(h, req)
			var got response
			_ = json.Unmarshal(rr.Body.Bytes(), &got)
			if rr.Code != 401 || got.Error == nil || got.Error.Message != c.want {
				t.Fatalf("status=%d error=%+v want %q", rr.Code, got.Error, c.want)
			}
		})
	}
}

func TestDeviceIntegrityWithoutLabelsIsEvaluatedEmpty(t *testing.T) {
	req := validRequest()
	p := goodPayload("com.test.app", time.Now(), reqHash(req))
	p.DeviceIntegrity.DeviceRecognitionVerdict = nil
	rr := serve(testHandler(p, nil), req)
	var got response
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != 200 || got.Risk.Provider != "detected" || got.Verdicts.DeviceRecognition == nil {
		t.Fatalf("status=%d provider=%+v", rr.Code, got.Risk)
	}
}
func TestCredentialAndUpstreamErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{{"credentials", &credentialError{context.DeadlineExceeded}, 503, "credentials_unavailable"}, {"upstream", context.DeadlineExceeded, 502, "verification_unavailable"}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := serve(handler{packageName: "com.test.app", now: time.Now, decode: func(context.Context, string) (*decoded, error) { return nil, c.err }}, validRequest())
			var got response
			_ = json.Unmarshal(rr.Body.Bytes(), &got)
			if rr.Code != c.status || got.Error == nil || got.Error.Code != c.code {
				t.Fatalf("status=%d error=%+v", rr.Code, got.Error)
			}
		})
	}
}

type failingTokenSource struct{}

func (failingTokenSource) Token() (*oauth2.Token, error) { return nil, context.DeadlineExceeded }
func TestCredentialTokenSourceMarksCredentialFailure(t *testing.T) {
	_, err := (credentialTokenSource{source: failingTokenSource{}}).Token()
	var credentialFailure *credentialError
	if !errors.As(err, &credentialFailure) {
		t.Fatalf("token source error was not classified as a credential failure: %v", err)
	}
}
func TestFailedBaselinesPrecedeUnevaluatedBaselines(t *testing.T) {
	for _, c := range []struct{ app, license string }{{"UNRECOGNIZED_VERSION", "UNEVALUATED"}, {"UNEVALUATED", "UNLICENSED"}} {
		req := validRequest()
		p := goodPayload("com.test.app", time.Now(), reqHash(req))
		p.AppIntegrity.AppRecognitionVerdict = c.app
		p.AccountDetails.AppLicensingVerdict = c.license
		rr := serve(testHandler(p, nil), req)
		var got response
		_ = json.Unmarshal(rr.Body.Bytes(), &got)
		if rr.Code != 200 || got.Decision != "restrict" {
			t.Fatalf("%s/%s decision=%s", c.app, c.license, got.Decision)
		}
	}
}
func TestBaselineGates(t *testing.T) {
	for _, c := range []struct{ app, license, decision string }{{"UNRECOGNIZED_VERSION", "LICENSED", "restrict"}, {"PLAY_RECOGNIZED", "UNLICENSED", "restrict"}, {"UNEVALUATED", "LICENSED", "review"}} {
		req := validRequest()
		p := goodPayload("com.test.app", time.Now(), reqHash(req))
		p.AppIntegrity.AppRecognitionVerdict = c.app
		p.AccountDetails.AppLicensingVerdict = c.license
		rr := serve(testHandler(p, nil), req)
		var got response
		_ = json.Unmarshal(rr.Body.Bytes(), &got)
		if rr.Code != 200 || got.Decision != c.decision {
			t.Fatalf("decision=%s want %s", got.Decision, c.decision)
		}
	}
}
func TestValidateSignalOrderingAndUnknownNames(t *testing.T) {
	r := validRequest()
	r.KitAvailable = boolPtr(true)
	r.KitSignals = []string{"root", "emulator"}
	if validate(r) == nil {
		t.Fatal("unsorted signals accepted")
	}
	r.KitSignals = []string{"notARealSignal"}
	if validate(r) == nil {
		t.Fatal("unknown signal accepted")
	}
}
func TestGoogleEnvelopeDecode(t *testing.T) {
	p := goodPayload("com.test.app", time.Now(), "hash")
	b, _ := json.Marshal(map[string]any{"tokenPayloadExternal": p})
	var d decoded
	if err := json.Unmarshal(b, &d); err != nil || d.TokenPayloadExternal == nil || d.TokenPayloadExternal.RequestDetails.TimestampMillis == "" {
		t.Fatal("Google envelope was not decoded")
	}
}
func validRequest() request {
	available := false
	return request{Action: "sample-check", RequestID: "0123456789abcdef0123456789abcdef", Policy: "or", KitAvailable: &available, KitSignals: []string{}, IntegrityToken: "opaque-token"}
}
func reqHash(r request) string {
	s := sha256.Sum256([]byte("mhk-sample-v1\n" + r.Action + "\n" + r.RequestID + "\n" + r.Policy + "\n" + boolText(*r.KitAvailable) + "\n" + strings.Join(r.KitSignals, ",")))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
func formatMillis(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }
func goodPayload(pkg string, at time.Time, hash string) *payload {
	return &payload{RequestDetails: &struct {
		RequestPackageName string `json:"requestPackageName"`
		TimestampMillis    string `json:"timestampMillis"`
		RequestHash        string `json:"requestHash"`
	}{pkg, formatMillis(at), hash}, AppIntegrity: &struct {
		AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
		PackageName             string   `json:"packageName"`
		CertificateSha256Digest []string `json:"certificateSha256Digest"`
		VersionCode             string   `json:"versionCode"`
	}{"PLAY_RECOGNIZED", pkg, []string{}, "1"}, AccountDetails: &struct {
		AppLicensingVerdict string `json:"appLicensingVerdict"`
	}{"LICENSED"}, DeviceIntegrity: &struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	}{[]string{"MEETS_DEVICE_INTEGRITY"}}}
}
func testHandler(p *payload, err error) handler {
	return handler{packageName: "com.test.app", now: time.Now, decode: func(context.Context, string) (*decoded, error) { return &decoded{TokenPayloadExternal: p}, err }}
}
func serve(h handler, r request) *httptest.ResponseRecorder {
	b, _ := json.Marshal(r)
	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}
func boolPtr(v bool) *bool { return &v }
