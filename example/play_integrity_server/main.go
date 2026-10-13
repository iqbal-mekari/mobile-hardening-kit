package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	playScope       = "https://www.googleapis.com/auth/playintegrity"
	maxBody         = 64 << 10
	maxAge          = 120 * time.Second
	futureTolerance = 30 * time.Second
)

type request struct {
	Action         string   `json:"action"`
	RequestID      string   `json:"requestId"`
	Policy         string   `json:"policy"`
	KitAvailable   *bool    `json:"kitAvailable"`
	KitSignals     []string `json:"kitSignals"`
	IntegrityToken string   `json:"integrityToken"`
}
type decodeRequest struct {
	IntegrityToken string `json:"integrity_token"`
}
type decoded struct {
	TokenPayloadExternal *payload `json:"tokenPayloadExternal"`
}
type payload struct {
	RequestDetails *struct {
		RequestPackageName string `json:"requestPackageName"`
		TimestampMillis    string `json:"timestampMillis"`
		RequestHash        string `json:"requestHash"`
	} `json:"requestDetails"`
	AppIntegrity *struct {
		AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
		PackageName             string   `json:"packageName"`
		CertificateSha256Digest []string `json:"certificateSha256Digest"`
		VersionCode             string   `json:"versionCode"`
	} `json:"appIntegrity"`
	AccountDetails *struct {
		AppLicensingVerdict string `json:"appLicensingVerdict"`
	} `json:"accountDetails"`
	DeviceIntegrity *struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
}
type response struct {
	Verification string    `json:"verification"`
	Policy       string    `json:"policy,omitempty"`
	Verdicts     *verdicts `json:"verdicts,omitempty"`
	Risk         *risk     `json:"risk,omitempty"`
	Decision     string    `json:"decision,omitempty"`
	Reasons      []string  `json:"reasons,omitempty"`
	Error        *apiError `json:"error,omitempty"`
}
type verdicts struct {
	AppRecognition    any `json:"appRecognition"`
	AppLicensing      any `json:"appLicensing"`
	DeviceRecognition any `json:"deviceRecognition"`
}
type credentialTokenSource struct{ source oauth2.TokenSource }

func (s credentialTokenSource) Token() (*oauth2.Token, error) {
	token, err := s.source.Token()
	if err != nil {
		return nil, &credentialError{err}
	}
	return token, nil
}

type risk struct {
	Kit      string `json:"kit"`
	Provider string `json:"provider"`
	Combined string `json:"combined"`
}
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type credentialError struct{ error }
type googleDecoder struct {
	packageName string
	client      *http.Client
}

func (g *googleDecoder) Decode(ctx context.Context, token string) (*decoded, error) {
	url := "https://playintegrity.googleapis.com/v1/" + g.packageName + ":decodeIntegrityToken"
	body, err := json.Marshal(decodeRequest{IntegrityToken: token})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("Google response exceeded size limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Google decode returned HTTP %d", res.StatusCode)
	}
	var out decoded
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("invalid Google response")
	}
	return &out, nil
}
func newGoogleDecoder(packageName string) (*googleDecoder, error) {
	credentialHTTP := &http.Client{Timeout: 10 * time.Second}
	credentialCtx := context.WithValue(context.Background(), oauth2.HTTPClient, credentialHTTP)
	creds, err := google.FindDefaultCredentials(credentialCtx, playScope)
	if err != nil {
		return nil, &credentialError{err}
	}
	tokenSource := credentialTokenSource{source: creds.TokenSource}
	client := oauth2.NewClient(credentialCtx, tokenSource)
	client.Timeout = 10 * time.Second
	return &googleDecoder{packageName: packageName, client: client}, nil
}

type handler struct {
	packageName string
	decode      func(context.Context, string) (*decoded, error)
	now         func() time.Time
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]string{"status": "ready"})
		return
	}
	if r.URL.Path != "/check" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "Use POST /check")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var in request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, 400, "invalid_request", "Request JSON is invalid or too large")
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, 400, "invalid_request", "Request must contain one JSON object")
		return
	}
	if err := validate(in); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	canonical := fmt.Sprintf("mhk-sample-v1\n%s\n%s\n%s\n%s\n%s", in.Action, in.RequestID, in.Policy, boolText(*in.KitAvailable), strings.Join(in.KitSignals, ","))
	expected := sha256.Sum256([]byte(canonical))
	expectedHash := base64.RawURLEncoding.EncodeToString(expected[:])
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	got, err := h.decode(ctx, in.IntegrityToken)
	if err != nil {
		var unavailable *credentialError
		if errors.As(err, &unavailable) {
			log.Printf("verification failure stage=credentials category=adc_or_token_source")
			writeError(w, 503, "credentials_unavailable", "Verification credentials are unavailable; ask the backend operator to check ADC configuration.")
			return
		}
		log.Printf("verification failure stage=decode category=upstream")
		writeError(w, 502, "verification_unavailable", "Verification could not complete; submit a new sample check later.")
		return
	}
	out, err := h.evaluate(got, in, expectedHash)
	if err != nil {
		writeError(w, 401, "verification_invalid", err.Error())
		return
	}
	writeJSON(w, 200, out)
}
func (h handler) evaluate(d *decoded, in request, expectedHash string) (response, error) {
	if d == nil || d.TokenPayloadExternal == nil || d.TokenPayloadExternal.RequestDetails == nil {
		return response{}, errors.New("Required request details are missing")
	}
	p := d.TokenPayloadExternal
	rd := p.RequestDetails
	if rd.RequestPackageName != h.packageName {
		return response{}, errors.New("Request package does not match configured package")
	}
	if rd.RequestHash != expectedHash {
		return response{}, errors.New("Google request hash does not match")
	}
	millis, err := strconv.ParseInt(rd.TimestampMillis, 10, 64)
	if err != nil {
		return response{}, errors.New("Integrity token timestamp is invalid")
	}
	t := time.UnixMilli(millis)
	now := h.now()
	if t.Before(now.Add(-maxAge)) || t.After(now.Add(futureTolerance)) {
		return response{}, errors.New("Integrity token is outside the accepted time window")
	}
	v := verdicts{}
	if p.AppIntegrity != nil {
		app := p.AppIntegrity
		if app.AppRecognitionVerdict != "UNEVALUATED" && app.PackageName != "" && app.PackageName != h.packageName {
			return response{}, errors.New("App package does not match configured package")
		}
		switch app.AppRecognitionVerdict {
		case "PLAY_RECOGNIZED":
			if app.PackageName == "" {
				return response{}, errors.New("Recognized app package is missing")
			}
			v.AppRecognition = "PLAY_RECOGNIZED"
		case "UNRECOGNIZED_VERSION":
			v.AppRecognition = "UNRECOGNIZED_VERSION"
		case "UNEVALUATED":
		default:
			return response{}, errors.New("App recognition verdict is unknown")
		}
	}
	if p.AccountDetails != nil {
		switch p.AccountDetails.AppLicensingVerdict {
		case "LICENSED", "UNLICENSED":
			v.AppLicensing = p.AccountDetails.AppLicensingVerdict
		case "UNEVALUATED", "":
		default:
			return response{}, errors.New("App licensing verdict is unknown")
		}
	}
	kit := "unavailable"
	if *in.KitAvailable {
		for _, s := range in.KitSignals {
			if kitSignalRisk[s] {
				kit = "detected"
				break
			}
		}
	}
	provider := "unavailable"
	if p.DeviceIntegrity != nil {
		labels := p.DeviceIntegrity.DeviceRecognitionVerdict
		if labels == nil {
			labels = []string{}
		}
		v.DeviceRecognition = labels
		provider = "detected"
		for _, label := range labels {
			if !validDeviceLabel[label] {
				return response{}, errors.New("Device recognition verdict contains an unknown label")
			}
			if label == "MEETS_DEVICE_INTEGRITY" {
				provider = "notDetected"
			}
		}
	}
	combined := reduce(in.Policy, kit, provider)
	decision := "allow"
	reasons := []string{fmt.Sprintf("Policy %s combined kit=%s and provider=%s into %s.", in.Policy, kit, provider, combined)}
	switch {
	case v.AppRecognition == "UNRECOGNIZED_VERSION" || v.AppLicensing == "UNLICENSED":
		decision = "restrict"
		reasons = append(reasons, "Play app recognition or licensing baseline did not pass.")
	case v.AppRecognition == nil || v.AppLicensing == nil:
		decision = "review"
		reasons = append(reasons, "App recognition or licensing was not evaluated.")
	case combined == "detected":
		decision = "review"
		reasons = append(reasons, "Policy "+in.Policy+" combined kit="+kit+" and provider="+provider+" into detected; review is illustrative, not production authorization.")
	case combined == "unavailable":
		decision = "review"
		reasons = append(reasons, "Policy "+in.Policy+" combined kit="+kit+" and provider="+provider+" into unavailable; review is illustrative, not production authorization.")
	default:
		reasons = append(reasons, "Play baselines passed. This is an illustrative sample policy, not production authorization.")
	}
	return response{Verification: "verified", Policy: in.Policy, Verdicts: &v, Risk: &risk{Kit: kit, Provider: provider, Combined: combined}, Decision: decision, Reasons: reasons}, nil
}

var kitSignalRisk = map[string]bool{"root": true, "jailbreak": true, "instrumentation": true, "debuggerAttach": true, "emulator": true, "devModeEnabled": true}
var knownSignals = map[string]bool{"root": true, "jailbreak": true, "instrumentation": true, "debuggerAttach": true, "signatureMismatch": true, "emulator": true, "accessibilityUnrecognized": true, "devModeEnabled": true, "screenCaptureActive": true, "screenshotTaken": true, "externalDisplay": true}
var validDeviceLabel = map[string]bool{"MEETS_DEVICE_INTEGRITY": true, "MEETS_BASIC_INTEGRITY": true, "MEETS_STRONG_INTEGRITY": true, "MEETS_VIRTUAL_INTEGRITY": true}

func validate(r request) error {
	if r.Action != "sample-check" || len(r.RequestID) != 32 {
		return errors.New("action or requestId is invalid")
	}
	for _, c := range r.RequestID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("requestId must be 32 lowercase hexadecimal characters")
		}
	}
	if r.Policy != "or" && r.Policy != "and" && r.Policy != "kitPrecedence" && r.Policy != "providerPrecedence" {
		return errors.New("policy is invalid")
	}
	if r.KitAvailable == nil {
		return errors.New("kitAvailable is required")
	}
	if r.KitSignals == nil {
		return errors.New("kitSignals is required")
	}
	if !*r.KitAvailable && len(r.KitSignals) > 0 {
		return errors.New("kitSignals must be empty when kitAvailable is false")
	}
	last := ""
	for _, s := range r.KitSignals {
		if !knownSignals[s] || s <= last {
			return errors.New("kitSignals must contain unique valid names in lexicographic order")
		}
		last = s
	}
	if strings.TrimSpace(r.IntegrityToken) == "" || len(r.IntegrityToken) > 32768 {
		return errors.New("integrityToken is required and must be bounded")
	}
	return nil
}
func reduce(policy, kit, provider string) string {
	if policy == "kitPrecedence" {
		if kit != "unavailable" {
			return kit
		}
		return provider
	}
	if policy == "providerPrecedence" {
		if provider != "unavailable" {
			return provider
		}
		return kit
	}
	if kit == "unavailable" {
		return provider
	}
	if provider == "unavailable" {
		return kit
	}
	if policy == "and" {
		if kit == "detected" && provider == "detected" {
			return "detected"
		}
		return "notDetected"
	}
	if kit == "detected" || provider == "detected" {
		return "detected"
	}
	return "notDetected"
}
func boolText(v bool) string {
	if v {
		return "available"
	}
	return "unavailable"
}
func main() {
	pkg := os.Getenv("PLAY_INTEGRITY_PACKAGE_NAME")
	if pkg == "" {
		pkg = "com.mekari.mobile_hardening_kit_example"
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	var mu sync.Mutex
	var verifier *googleDecoder
	decode := func(ctx context.Context, token string) (*decoded, error) {
		mu.Lock()
		if verifier == nil {
			candidate, err := newGoogleDecoder(pkg)
			if err != nil {
				mu.Unlock()
				return nil, err
			}
			verifier = candidate
		}
		current := verifier
		mu.Unlock()
		return current.Decode(ctx, token)
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler{packageName: pkg, decode: decode, now: time.Now})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("sample verification service listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, response{Verification: "error", Error: &apiError{Code: code, Message: message}})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
