package tests

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TaTrap/request-anything/internal/auto"
	"github.com/TaTrap/request-anything/internal/capture"
	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/internal/flow"
	"github.com/TaTrap/request-anything/internal/fuzz"
	"github.com/TaTrap/request-anything/internal/gate"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/mcp"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/oracle"
	"github.com/TaTrap/request-anything/internal/redact"
	"github.com/TaTrap/request-anything/internal/report"
	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/internal/shadow"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"github.com/bogdanfinn/tls-client/profiles"
	"google.golang.org/protobuf/encoding/protowire"
)

func computeStub(b []byte) string {
	sum := md5.Sum(b)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func makeProtoSample(deviceID string, version uint64) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, version)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, deviceID)
	return b
}

// Vertical Slice 1:
// Unsigned POST with EscapeSolidus (`\/`), raw numbers (`3.0`), literal `*` (`resolution=1216*2623`),
// empty `iid=`, duplicate keys, trailing `&`, Cronet H2 cookie crumbs, ForceHTTP1Raw non-canonical casing,
// schema-less protowire mismatch detection, full Go gate (`gofmt`/`go vet`/`go test`), and `secret-hygiene`.
func TestE2E_Slice1_LosslessWireEscapeSolidusQueryProtoAndSecretHygiene(t *testing.T) {
	ctx := context.Background()

	proxy, err := capture.StartLoopbackProxy(func(r *models.WireRequest) *models.WireResponse {
		return &models.WireResponse{
			Status:  200,
			Headers: []models.HeaderKV{{RawName: "content-type", Value: "application/json"}},
			Body:    models.WireBody{RawBytes: []byte(`{"status_code":0,"device_id":"7311001"}`), Encoding: "raw"},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Build JSON body using OrderedJSON with Android EscapeSolidus (`\/`) and exact raw float (`3.0`)
	om := wireclient.NewOrderedMap()
	om.Set("url", "https://v16.example.com/v2/feed/")
	om.Set("count", json.Number("3.0"))
	bodyBytes, err := wireclient.MarshalOrdered(om, wireclient.JSONMarshalOptions{EscapeSolidus: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(bodyBytes) != `{"url":"https:\/\/v16.example.com\/v2\/feed\/","count":3.0}` {
		t.Fatalf("unexpected EscapeSolidus body: %s", bodyBytes)
	}

	stub := computeStub(bodyBytes)
	rawQuery := "iid=&resolution=1216*2623&app_id=1001&app_id=1001&"
	pseudoOrder := []string{":method", ":path", ":authority", ":scheme"}

	client, err := wireclient.NewClient(wireclient.ClientOptions{
		Profile:  profiles.Okhttp4Android13,
		ProxyURL: proxy.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}

	hdrs := wireclient.NewOrderedHeaders(nil)
	hdrs.Add("content-md5", stub)
	hdrs.Add("cookie", "locale=en_US; region=US")
	hdrs.Add("content-type", "application/json")

	wireReqOut := &wireclient.OrderedRequest{
		Method:         "POST",
		Scheme:         "https",
		Authority:      "api.example.com",
		RawPath:        "/v2/feed/",
		Query:          wireclient.ParseRawQuery(rawQuery),
		Headers:        hdrs,
		CookieWireMode: models.CookieH2Crumbs,
		PseudoOrder:    pseudoOrder,
		Body:           bodyBytes,
	}

	// Capture actual wire baseline from LoopbackProxy (HTTP/2 + TLS ClientHello JA3/JA4 + Cronet H2 crumbs)
	if _, err := client.Do(ctx, wireReqOut); err != nil {
		t.Fatalf("wireclient H2 baseline failed: %v", err)
	}
	caps := proxy.Captured()
	if len(caps) != 1 {
		t.Fatalf("expected 1 baseline capture, got %d", len(caps))
	}
	baseline := *caps[0]
	if baseline.Transport.CookieWireMode != models.CookieH2Crumbs {
		t.Fatalf("expected CookieH2Crumbs, got %s", baseline.Transport.CookieWireMode)
	}
	if !baseline.TrailingAmp || baseline.RawQuery != rawQuery {
		t.Fatalf("expected verbatim trailing `&` and `*`, got %+v", baseline)
	}
	if !baseline.Body.JSONStyle.EscapeSolidus {
		t.Fatalf("expected EscapeSolidus auto-detected on captured body")
	}

	// Scaffold a real Go unit inside module root so SkipGoChecks:false runs real gofmt/go vet/go test
	testsWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Dir(testsWD)
	unitDir, err := os.MkdirTemp(repoRoot, "tmp_e2e_slice1_*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(unitDir) })

	fix := &models.GoldenFixture{
		Schema:   models.SchemaFixture,
		ID:       "e2e-slice1-feed",
		Name:     "feed_post",
		Source:   "loopback_proxy",
		Request:  baseline,
		Response: &models.WireResponse{Status: 200, Body: models.WireBody{RawBytes: []byte(`{"status_code":0,"device_id":"7311001"}`)}},
	}
	if _, err := scaffold.Scaffold(scaffold.Options{
		Root:    repoRoot,
		OutDir:  unitDir,
		Fixture: fix,
		Force:   true,
	}); err != nil {
		t.Fatal(err)
	}

	// Re-send through LoopbackProxy as the ported Go request and run Full Hard Gate (SkipGoChecks: false)
	proxy.Reset()
	resp, err := client.Do(ctx, wireReqOut)
	if err != nil {
		t.Fatal(err)
	}
	caps2 := proxy.Captured()
	if len(caps2) != 1 {
		t.Fatalf("expected 1 replay capture, got %d", len(caps2))
	}

	gateOut, err := gate.Evaluate(ctx, gate.Options{
		UnitDir:         unitDir,
		ActualRequests:  caps2,
		ActualResponses: []*models.WireResponse{{Status: resp.Status, Body: models.WireBody{RawBytes: resp.Body}}},
		ReqIDCorrelated: true,
		SkipGoChecks:    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gateOut.Passed {
		t.Fatalf("expected Slice 1 full Go gate PASS, got checks=%+v", gateOut.Checks)
	}

	// Verify ForceHTTP1Raw preserves exact non-canonical header casing across LoopbackProxy
	proxy.Reset()
	h1Hdrs := wireclient.NewOrderedHeaders(nil)
	h1Hdrs.Add("Host", "api.example.com")
	h1Hdrs.Add("x-Custom-MixedCase", "val-1")
	h1Resp, err := client.Do(ctx, &wireclient.OrderedRequest{
		Method:        "POST",
		Scheme:        "https",
		Authority:     "api.example.com",
		RawPath:       "/v2/feed/",
		Query:         wireclient.ParseRawQuery("iid=&"),
		Headers:       h1Hdrs,
		Body:          []byte("{}"),
		ForceHTTP1Raw: true,
	})
	if err != nil || h1Resp.Status != 200 {
		t.Fatalf("ForceHTTP1Raw failed: status=%v err=%v", h1Resp, err)
	}
	h1Caps := proxy.Captured()
	if len(h1Caps) != 1 || len(h1Caps[0].Headers) < 2 || h1Caps[0].Headers[1].RawName != "x-Custom-MixedCase" {
		t.Fatalf("expected exact non-canonical HTTP/1.1 header casing preserved, got %+v", h1Caps)
	}

	// Deliberate 1-byte wire mismatches must FAIL Gate & Diff:
	// (a) Unescaped `/` instead of `\/` (changes body MD5 digest & raw JSON bytes)
	spec, _ := contract.Load(unitDir)
	badSolidus := *caps2[0]
	badSolidus.Body.RawBytes = []byte(`{"url":"https://v16.example.com/v2/feed/","count":3.0}`)
	ingest.FinalizeBody(&badSolidus.Body, "application/json")
	if d := diff.CompareRequests(ctx, "bad-solidus", &fix.Request, &badSolidus, nil, nil, diff.Options{Contract: spec}); d.Passed {
		t.Fatalf("expected unescaped solidus `/` mismatch to FAIL diff")
	}

	// (b) Percent-encoded `*` (%2A) & dropped trailing `&`
	badQuery := *caps2[0]
	badQuery.TrailingAmp = false
	badQuery.RawQuery = "iid=&resolution=1216%2A2623&app_id=1001&app_id=1001"
	badQuery.Query = wireclient.ParseRawQuery(badQuery.RawQuery).Params
	if gBad, gErr := gate.Evaluate(ctx, gate.Options{
		UnitDir:         unitDir,
		ActualRequests:  []*models.WireRequest{&badQuery},
		ReqIDCorrelated: true,
		SkipGoChecks:    true,
	}); gErr != nil || gBad.Passed {
		t.Fatalf("expected mutated query (`%%2A` and missing trailing `&`) to FAIL gate")
	}

	// (c) Schema-less protowire 1-byte varint mismatch
	protoExp := makeProtoSample("7311001", 1)
	protoAct := makeProtoSample("7311001", 2)
	if pf := diff.DiffProtoWire("body.proto", protoExp, protoAct); len(pf) == 0 {
		t.Fatalf("expected protowire varint mismatch finding without .proto schema")
	}

	// (d) Secret-hygiene rejects PEM private key inside unit directory
	leakPath := filepath.Join(unitDir, "leaked_fixture.json")
	if err := os.WriteFile(leakPath, []byte(`{"key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	gLeak, err := gate.Evaluate(ctx, gate.Options{
		UnitDir:         unitDir,
		ActualRequests:  caps2,
		ReqIDCorrelated: true,
		SkipGoChecks:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gLeak.Passed {
		t.Fatalf("expected leaked RSA private key to FAIL secret-hygiene check")
	}
	_ = os.Remove(leakPath)
}

// Vertical Slice 2:
// Signed request with Simulated Random IV (`oracle_verify` decoding Signature claims & checking body_md5 + app_id),
// portable NativeSnapshot surviving a simulated JVM/sidecar restart, and Coverage Honesty unknowns for `lossy_har`.
func TestE2E_Slice2_OracleVerifyPortableSnapshotAndCoverageHonesty(t *testing.T) {
	ctx := context.Background()

	mock1 := oracle.NewMockOracle()
	mock1.SimulateRandomIV = true
	so1 := oracle.NewSerializedOracle(mock1)

	h1, err := so1.Open(ctx, oracle.SessionConfig{
		AppVersion: "36.5.0",
		DeviceID:   "7311223344",
		InstallID:  "7311998877",
		PinnedSeed: 42,
		NowMs:      1700000100000,
	})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"feed_type":0,"path":"\/v2\/feed\/"}`)
	rawQuery := "app_id=1001&ts=1700000100"
	sign1, err := so1.Sign(ctx, h1, "req-sign-1", oracle.SignInput{
		Method:   "POST",
		URL:      "/v2/feed/",
		RawQuery: rawQuery,
		Body:     body,
		NowMs:    1700000100000,
	})
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := capture.StartLoopbackProxy(func(r *models.WireRequest) *models.WireResponse {
		return &models.WireResponse{Status: 200, Body: models.WireBody{RawBytes: []byte(`{"status_code":0}`)}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Lossy HAR baseline intentionally omits TLS JA4 / H2 SETTINGS to verify Coverage Honesty Unknowns
	expFix := &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     "slice2-signed-har",
		Name:   "signed_feed",
		Source: "har",
		Request: models.WireRequest{
			Schema:    models.SchemaFixture,
			Method:    "POST",
			Scheme:    "https",
			Authority: "api.example.com",
			RawPath:   "/v2/feed/",
			RawQuery:  rawQuery,
			Query:     wireclient.ParseRawQuery(rawQuery).Params,
			Headers: []models.HeaderKV{
				{RawName: "content-md5", Value: sign1.Headers["content-md5"]},
				{RawName: "x-timestamp", Value: sign1.Headers["x-timestamp"]},
				{RawName: "x-signature", Value: sign1.Headers["x-signature"]},
				{RawName: "signature", Value: sign1.Headers["signature"]},
				{RawName: "content-type", Value: "application/json"},
				{RawName: "content-length", Value: fmt.Sprintf("%d", len(body))},
			},
			Body: models.WireBody{RawBytes: body, Encoding: "raw"},
			Transport: models.TransportMeta{
				CaptureFidelity: models.FidelityLossyHAR,
				CookieWireMode:  models.CookieSingleHeader,
				Proto:           "HTTP/2",
			},
		},
	}
	ingest.FinalizeBody(&expFix.Request.Body, "application/json")

	unitDir := filepath.Join(t.TempDir(), "slice2_unit")
	if _, err := scaffold.Scaffold(scaffold.Options{
		Root:    filepath.Dir(unitDir),
		OutDir:  unitDir,
		Fixture: expFix,
		Force:   true,
	}); err != nil {
		t.Fatal(err)
	}

	// Serialize portable NativeSnapshot to disk and shut down original mock1 oracle
	snap, err := so1.Snapshot(ctx, h1)
	if err != nil {
		t.Fatal(err)
	}
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(t.TempDir(), "native_snapshot.json")
	if err := os.WriteFile(snapPath, snapJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = so1.Close(ctx, h1)

	// Simulate fresh sidecar/JVM restart with brand-new MockOracle and restore portable snapshot from disk
	diskBytes, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	var loadedSnap oracle.NativeSnapshot
	if err := json.Unmarshal(diskBytes, &loadedSnap); err != nil {
		t.Fatal(err)
	}

	mock2 := oracle.NewMockOracle()
	mock2.SimulateRandomIV = true
	so2 := oracle.NewSerializedOracle(mock2)
	h2, err := so2.Open(ctx, oracle.SessionConfig{AppVersion: "36.5.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := so2.Restore(ctx, h2, &loadedSnap); err != nil {
		t.Fatalf("portable snapshot restore on fresh oracle failed: %v", err)
	}

	// Sign again after restore: Signature differs byte-for-byte because SimulateRandomIV=true,
	// yet oracle_verify must PASS because body_md5 and app_id claims inside Signature bind cleanly.
	sign2, err := so2.Sign(ctx, h2, "req-sign-2", oracle.SignInput{
		Method:   "POST",
		URL:      "/v2/feed/",
		RawQuery: rawQuery,
		Body:     body,
		NowMs:    1700000200000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sign2.Headers["signature"] == sign1.Headers["signature"] {
		t.Fatalf("expected different random-IV Signature after restart")
	}

	client, err := wireclient.NewClient(wireclient.ClientOptions{
		Profile:  profiles.Okhttp4Android13,
		ProxyURL: proxy.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}
	hdrs := wireclient.NewOrderedHeaders([]models.HeaderKV{
		{RawName: "content-md5", Value: sign2.Headers["content-md5"]},
		{RawName: "x-timestamp", Value: sign2.Headers["x-timestamp"]},
		{RawName: "x-signature", Value: sign2.Headers["x-signature"]},
		{RawName: "signature", Value: sign2.Headers["signature"]},
		{RawName: "content-type", Value: "application/json"},
	})
	if _, err := client.Do(ctx, &wireclient.OrderedRequest{
		Method:    "POST",
		Scheme:    "https",
		Authority: "api.example.com",
		RawPath:   "/v2/feed/",
		Query:     wireclient.ParseRawQuery(rawQuery),
		Headers:   hdrs,
		Body:      body,
	}); err != nil {
		t.Fatal(err)
	}

	gateOut, err := gate.Evaluate(ctx, gate.Options{
		UnitDir:         unitDir,
		ActualRequests:  proxy.Captured(),
		ReqIDCorrelated: true,
		SkipGoChecks:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gateOut.Passed {
		t.Fatalf("expected Slice 2 oracle_verify gate PASS despite random IV, checks=%+v", gateOut.Checks)
	}
	if len(gateOut.Unknowns) == 0 {
		t.Fatalf("expected Coverage Honesty to emit explicit Unknowns for lossy_har baseline")
	}
}

// Vertical Slice 3:
// All 4 Mandatory Regressions:
//
//	(a) iid= empty & dual-fail status-200 error_code=7 caught by Positive Assertions;
//	(b) mismatched reqID DeliverResponse rejected (anti-FIFO);
//	(c) injected native worker exception fails zero_native_exceptions gate check;
//	(d) full multi-step DAG (branch_on 4029, parallel_group burst, async /telemetry/report pump,
//	    portable disk snapshot restore across fresh oracle, and LiftFlow 0% fallback guard).
func TestE2E_Slice3_MandatoryRegressionsAndFlowDAG(t *testing.T) {
	ctx := context.Background()

	// --- Regression A: `iid=` empty & dual-fail error_code=7 false-green trap ---
	regFix := &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     "reg-device-register",
		Name:   "device_register",
		Source: "curl",
		Request: models.WireRequest{
			Schema:    models.SchemaFixture,
			Method:    "POST",
			Scheme:    "https",
			Authority: "api.example.com",
			RawPath:   "/v1/device/register",
			RawQuery:  "iid=111&app_id=1001",
			Query:     wireclient.ParseRawQuery("iid=111&app_id=1001").Params,
			Headers:   []models.HeaderKV{{RawName: "content-type", Value: "application/json"}},
			Body:      models.WireBody{RawBytes: []byte(`{"client_tag":"mobile_sdk"}`), Encoding: "raw"},
			Transport: models.TransportMeta{CaptureFidelity: models.FidelityHookDump, Proto: "HTTP/2"},
		},
		Response: &models.WireResponse{Status: 200, Body: models.WireBody{RawBytes: []byte(`{"device_id":"731999","install_id":"731888"}`)}},
	}
	ingest.FinalizeBody(&regFix.Request.Body, "application/json")

	regUnit := filepath.Join(t.TempDir(), "reg_unit")
	if _, err := scaffold.Scaffold(scaffold.Options{Root: filepath.Dir(regUnit), OutDir: regUnit, Fixture: regFix, Force: true}); err != nil {
		t.Fatal(err)
	}
	// Dual-fail: HTTP 200 with error_code=7 and empty device_id=""
	badQueryReq := regFix.Request
	badQueryReq.RawQuery = "iid=&app_id=1001"
	badQueryReq.Query = wireclient.ParseRawQuery("iid=&app_id=1001").Params
	badResp := &models.WireResponse{
		Status: 200,
		Body:   models.WireBody{RawBytes: []byte(`{"error_code":7,"device_id":""}`)},
	}
	gDualFail, err := gate.Evaluate(ctx, gate.Options{
		UnitDir:         regUnit,
		ActualRequests:  []*models.WireRequest{&badQueryReq},
		ActualResponses: []*models.WireResponse{badResp},
		ReqIDCorrelated: true,
		SkipGoChecks:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gDualFail.Passed {
		t.Fatalf("Regression A failed: HTTP 200 error_code=7 with empty device_id / iid= falsely passed gate")
	}

	// --- Regression B & C setup with Stateful MockOracle ---
	mOracle := oracle.NewMockOracle()
	so := oracle.NewSerializedOracle(mOracle)
	h, err := so.Open(ctx, oracle.SessionConfig{AppVersion: "36.5.0", DeviceID: "0", InstallID: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Sign(ctx, h, "req-good-1", oracle.SignInput{Method: "POST", URL: "/v1/device/register"}); err != nil {
		t.Fatal(err)
	}

	// Regression B: Anti-FIFO mismatched reqID must error
	if _, derr := so.DeliverResponse(ctx, h, "req-wrong-fifo-id", &models.WireResponse{Status: 200}); derr == nil {
		t.Fatalf("Regression B failed: expected DeliverResponse to reject uncorrelated reqID")
	}
	// Deliver genuine reqID cleanly
	if _, derr := so.DeliverResponse(ctx, h, "req-good-1", &models.WireResponse{Status: 200}); derr != nil {
		t.Fatalf("expected valid reqID delivery to succeed: %v", derr)
	}

	// Regression C: Inject unhandled native worker exception -> zero_native_exceptions MUST fail gate
	mOracle.InjectException(h, "java.lang.UnsatisfiedLinkError: libnativesig.so")
	healthErr, err := so.Health(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	gExc, err := gate.Evaluate(ctx, gate.Options{
		UnitDir:         regUnit,
		ActualRequests:  []*models.WireRequest{&regFix.Request},
		ActualResponses: []*models.WireResponse{regFix.Response},
		OracleHealth:    healthErr,
		ReqIDCorrelated: true,
		SkipGoChecks:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gExc.Passed {
		t.Fatalf("Regression C failed: gate passed despite native worker exception")
	}
	_ = so.Close(ctx, h)

	// --- Regression D: Full Flow DAG + parallel_group + branch_on 4029 + /telemetry/report + portable restore + LiftFlow ---
	flowOracle1 := oracle.NewMockOracle()
	flowSO1 := oracle.NewSerializedOracle(flowOracle1)
	fh1, err := flowSO1.Open(ctx, oracle.SessionConfig{AppVersion: "36.5.0", DeviceID: "init-did", InstallID: "init-iid"})
	if err != nil {
		t.Fatal(err)
	}

	flowDir := filepath.Join(t.TempDir(), "mobile_onboarding")
	if err := os.MkdirAll(flowDir, 0o755); err != nil {
		t.Fatal(err)
	}

	spec := &flow.FlowSpec{
		Schema: "request-anything/flow@1",
		Name:   "mobile_onboarding",
		Steps: []flow.Step{
			{
				ID:             "register",
				Name:           "device_register",
				Endpoint:       "device_register",
				Method:         "POST",
				RawPath:        "/v1/device/register",
				RawQuery:       "app_id=1001",
				Body:           `{"did":"{{device_id}}"}`,
				SignWithOracle: true,
				SnapshotBefore: true,
				BranchOn: []flow.BranchRule{
					{Status: 200, JSONPath: "status_code", Equals: "4029", NextStep: "captcha_recover"},
				},
			},
			{
				ID:             "captcha_recover",
				Name:           "captcha_verify",
				Endpoint:       "captcha",
				Method:         "POST",
				RawPath:        "/captcha/verify",
				SignWithOracle: true,
				SnapshotBefore: true,
			},
			{
				ID:             "feed_1",
				Name:           "feed_hot",
				Endpoint:       "feed",
				Method:         "GET",
				RawPath:        "/v2/feed/",
				RawQuery:       "did={{device_id}}",
				SignWithOracle: true,
				ParallelGroup:  "burst",
			},
			{
				ID:             "feed_2",
				Name:           "feed_follow",
				Endpoint:       "settings",
				Method:         "GET",
				RawPath:        "/v1/config/check",
				RawQuery:       "did={{device_id}}",
				SignWithOracle: true,
				ParallelGroup:  "burst",
			},
		},
	}
	if err := flow.SaveFlow(flowDir, spec); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var sentAsync []oracle.AsyncPacket
	var hitPaths []string
	var burstConcurrent atomic.Int32

	execFn := func(c context.Context, st *flow.SessionState, s flow.Step, reqID string) (*models.WireResponse, bool, error) {
		mu.Lock()
		hitPaths = append(hitPaths, s.ID+":"+s.RawPath)
		mu.Unlock()

		switch s.ID {
		case "register":
			return &models.WireResponse{
				Status: 200,
				Body:   models.WireBody{RawBytes: []byte(`{"status_code":4029,"device_id":"7319001","install_id":"7318001"}`)},
			}, false, nil
		case "captcha_recover":
			return &models.WireResponse{
				Status: 200,
				Body:   models.WireBody{RawBytes: []byte(`{"status_code":0,"captcha":"passed"}`)},
			}, false, nil
		case "feed_1", "feed_2":
			burstConcurrent.Add(1)
			time.Sleep(15 * time.Millisecond)
			if !strings.Contains(s.RawQuery, "did=7319001") {
				return nil, false, fmt.Errorf("expected expanded device_id in %s query %q", s.ID, s.RawQuery)
			}
			return &models.WireResponse{
				Status: 200,
				Body:   models.WireBody{RawBytes: []byte(`{"status_code":0}`)},
			}, false, nil
		default:
			return nil, false, fmt.Errorf("unexpected step %s", s.ID)
		}
	}

	r1 := &flow.Runner{
		FlowDir:  flowDir,
		Oracle:   flowSO1,
		Handle:   fh1,
		Executor: execFn,
		PacketSender: func(c context.Context, pkt oracle.AsyncPacket) error {
			mu.Lock()
			sentAsync = append(sentAsync, pkt)
			mu.Unlock()
			return nil
		},
	}
	out1, err := r1.Run(ctx, spec, "", nil)
	if err != nil {
		t.Fatalf("flow run failed: %v", err)
	}
	if !out1.Passed || !out1.ReqIDCorrelated {
		t.Fatalf("expected flow run PASS, got %+v", out1)
	}
	if len(out1.StepsExecuted) != 4 || out1.StepsExecuted[0].NextBranch != "captcha_recover" {
		t.Fatalf("expected branch_on 4029 + 4 executed steps, got %+v", out1.StepsExecuted)
	}
	if len(sentAsync) == 0 || sentAsync[0].Endpoint != "/telemetry/report" {
		t.Fatalf("expected /telemetry/report async packet pump, got %+v", sentAsync)
	}
	if _, err := os.Stat(filepath.Join(flowDir, ".request-anything", "snapshots", "captcha_recover.json")); err != nil {
		t.Fatalf("expected per-step portable snapshot on disk: %v", err)
	}
	_ = flowSO1.Close(ctx, fh1)

	// Resume from captcha_recover disk snapshot on a brand new MockOracle
	flowOracle2 := oracle.NewMockOracle()
	flowSO2 := oracle.NewSerializedOracle(flowOracle2)
	fh2, err := flowSO2.Open(ctx, oracle.SessionConfig{AppVersion: "36.5.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer flowSO2.Close(ctx, fh2)

	r2 := &flow.Runner{
		FlowDir:  flowDir,
		Oracle:   flowSO2,
		Handle:   fh2,
		Executor: execFn,
	}
	out2, err := r2.Run(ctx, spec, "captcha_recover", nil)
	if err != nil || !out2.Passed || len(out2.StepsExecuted) != 3 {
		t.Fatalf("resume from captcha_recover snapshot failed: err=%v out=%+v", err, out2)
	}

	// LiftFlow guard: must refuse non-zero fallback, accept 0% fallback and write LIFTED.md
	if err := flow.LiftFlow(flowDir, &flow.FlowOutcome{Passed: true, FallbackCount: 1, FallbackRate: 0.25}); err == nil {
		t.Fatalf("expected LiftFlow to reject >0%% fallback")
	}
	if err := flow.LiftFlow(flowDir, out1); err != nil {
		t.Fatalf("LiftFlow 0%% fallback failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(flowDir, "LIFTED.md")); err != nil {
		t.Fatalf("expected LIFTED.md created: %v", err)
	}
}

// Vertical Slice 4:
// Full MCP stdio JSON-RPC 2.0 round-trip (`initialize` -> `tools/list` -> `import` -> `scaffold` ->
// `diff` -> `gate` -> live HTTP `flow_replay` -> concurrency `ping` + `notifications/cancelled`).
func TestE2E_Slice4_MCPStdioRoundTripAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Live HTTP backend for MCP flow_replay
	var flowHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flowHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/step1" {
			_, _ = w.Write([]byte(`{"device_id":"did-mcp-99","status_code":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"query":"` + r.URL.RawQuery + `","status_code":0}`))
	}))
	defer srv.Close()

	workDir := t.TempDir()
	curlPath := filepath.Join(workDir, "sample.curl")
	if err := os.WriteFile(curlPath, []byte(`curl -X POST 'https://api.example.com/v1/echo?a=1&b=2&' -H 'content-type: application/json' -d '{"hello":"world"}'`), 0o644); err != nil {
		t.Fatal(err)
	}
	flowDir := filepath.Join(workDir, "flow")
	if err := os.MkdirAll(flowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := flow.SaveFlow(flowDir, &flow.FlowSpec{
		Schema:  "request-anything/flow@1",
		Name:    "mcp_flow",
		BaseURL: srv.URL,
		Steps: []flow.Step{
			{ID: "s1", Name: "step1", Endpoint: "s1", Method: "GET", RawPath: "/step1"},
			{ID: "s2", Name: "step2", Endpoint: "s2", Method: "GET", RawPath: "/step2", RawQuery: "did={{device_id}}"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- mcp.ServeIO(ctx, inR, outW)
		_ = outW.Close()
	}()

	enc := json.NewEncoder(inW)
	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 64*1024), 4<<20)

	readRespForID := func(wantID float64) map[string]any {
		for sc.Scan() {
			var msg map[string]any
			if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
				t.Fatalf("bad JSON from MCP: %v (%s)", err, sc.Text())
			}
			if id, ok := msg["id"].(float64); ok && id == wantID {
				return msg
			}
		}
		t.Fatalf("EOF waiting for MCP id %v (err=%v)", wantID, sc.Err())
		return nil
	}

	// 1. initialize & tools/list
	_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": mcp.ProtocolVersion}})
	r1 := readRespForID(1)
	if r1["error"] != nil {
		t.Fatalf("initialize error: %+v", r1)
	}
	_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	r2 := readRespForID(2)
	tools := r2["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 12 {
		t.Fatalf("expected 12 MCP tools, got %d", len(tools))
	}

	// 2. import -> scaffold -> diff -> gate (skip_go_checks: true inside TempDir) -> flow_replay
	fixturesOut := filepath.Join(workDir, "fixtures")
	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "import", "arguments": map[string]any{"source": curlPath, "out": fixturesOut, "format": "curl"}},
	})
	r3 := readRespForID(3)
	sc3 := r3["result"].(map[string]any)["structuredContent"].(map[string]any)
	fixPath := sc3["fixtures"].([]any)[0].(string)

	unitOut := filepath.Join(workDir, "mcp_unit")
	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "scaffold", "arguments": map[string]any{"fixture": fixPath, "out": unitOut, "force": true}},
	})
	r4 := readRespForID(4)
	if r4["result"].(map[string]any)["isError"] == true {
		t.Fatalf("MCP scaffold error: %+v", r4)
	}

	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{"name": "diff", "arguments": map[string]any{"unit": unitOut}},
	})
	r5 := readRespForID(5)
	if passed, _ := r5["result"].(map[string]any)["structuredContent"].(map[string]any)["passed"].(bool); !passed {
		t.Fatalf("MCP diff failed: %+v", r5)
	}

	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{"name": "gate", "arguments": map[string]any{"unit": unitOut, "skip_go_checks": true}},
	})
	r6 := readRespForID(6)
	if passed, _ := r6["result"].(map[string]any)["structuredContent"].(map[string]any)["passed"].(bool); !passed {
		t.Fatalf("MCP gate failed: %+v", r6)
	}

	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "flow_replay", "arguments": map[string]any{"flow_dir": flowDir}},
	})
	r7 := readRespForID(7)
	flowSC := r7["result"].(map[string]any)["structuredContent"].(map[string]any)
	if passed, _ := flowSC["passed"].(bool); !passed || flowHits.Load() != 2 {
		t.Fatalf("MCP flow_replay failed: hits=%d res=%+v", flowHits.Load(), r7)
	}

	// 3. Concurrency + cancellation: ping(9) beats slow sleep(8), cancelled sleep(10) emits zero response
	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 8, "method": "tools/call",
		"params": map[string]any{"name": "test_sleep", "arguments": map[string]any{"ms": 200}},
	})
	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "id": 10, "method": "tools/call",
		"params": map[string]any{"name": "test_sleep", "arguments": map[string]any{"ms": 4000}},
	})
	_ = enc.Encode(map[string]any{
		"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": 10},
	})
	_ = enc.Encode(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "ping"})
	_ = inW.Close()

	var tail []float64
	for sc.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			t.Fatal(err)
		}
		if id, ok := msg["id"].(float64); ok {
			tail = append(tail, id)
		}
	}
	if err := <-serveErrCh; err != nil {
		t.Fatalf("ServeIO returned error: %v", err)
	}
	if len(tail) != 2 || tail[0] != 9 || tail[1] != 8 {
		t.Fatalf("expected ping(9) then sleep(8) and NO cancelled(10), got order=%v", tail)
	}
}

// End-to-End Regression covering all 11 audited bugs:
// Bugs #1 & #2: Out-of-repo standalone compile (no internal/* imports) + diff/gate/auto kill false-green.
// Bug #3: L2 Cookie content mismatch caught even when crumb count matches.
// Bug #4: flow.Runner actually attaches Oracle.Sign headers on the wire.
// Bugs #5 & #6: RawQuery redaction + x-app-id preserved + binary //go:embed + refresh/map freshness sync.
// Bugs #7 & #11: Gzipped request/response parity, real MeasureAndWriteReport metrics, real compiled fuzz.
func TestE2E_Audit11BugsRegression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Build gzipped JSON response for device_register (tests Bug #7 decoded positive-assertions + L6)
	var gzResp bytes.Buffer
	gw := gzip.NewWriter(&gzResp)
	_, _ = gw.Write([]byte(`{"device_id":"731999","install_id":"731888","status_code":0}`))
	_ = gw.Close()

	// Build gzipped JSON request body + password in RawQuery + public x-app-id: 1001 (Bug #5)
	var gzReq bytes.Buffer
	rw := gzip.NewWriter(&gzReq)
	_, _ = rw.Write([]byte(`{"url":"https:\/\/v16.example.com\/register"}`))
	_ = rw.Close()

	extRepo := t.TempDir() // Completely outside repoRoot!
	outUnit := filepath.Join(extRepo, "devreg_unit")

	rawQuery := "app_id=1001&iid=731888&password=superSecret99&"
	regFix := &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     "audit-devreg",
		Name:   "device_register",
		Source: "curl",
		Request: models.WireRequest{
			Schema:      models.SchemaFixture,
			Method:      "POST",
			Scheme:      "https",
			Authority:   "api.example.com",
			RawPath:     "/v1/device/register",
			RawQuery:    rawQuery,
			TrailingAmp: true,
			Query:       wireclient.ParseRawQuery(rawQuery).Params,
			Headers: []models.HeaderKV{
				{RawName: "x-app-id", Value: "1001"},
				{RawName: "content-encoding", Value: "gzip"},
				{RawName: "content-type", Value: "application/json"},
			},
			Body: models.WireBody{RawBytes: gzReq.Bytes(), Encoding: "gzip"},
			Transport: models.TransportMeta{
				CaptureFidelity: models.FidelityHookDump,
				CookieWireMode:  models.CookieSingleHeader,
				Proto:           "HTTP/2",
			},
		},
		Response: &models.WireResponse{
			Status: 200,
			Headers: []models.HeaderKV{
				{RawName: "content-encoding", Value: "gzip"},
				{RawName: "content-type", Value: "application/json"},
			},
			Body: models.WireBody{RawBytes: gzResp.Bytes(), Encoding: "gzip"},
		},
	}
	ingest.FinalizeBody(&regFix.Request.Body, "application/json")
	ingest.FinalizeBody(&regFix.Response.Body, "application/json")

	scafOut, err := scaffold.Scaffold(scaffold.Options{
		Root:    extRepo,
		OutDir:  outUnit,
		Fixture: regFix,
		Force:   true,
	})
	if err != nil {
		t.Fatalf("external scaffold failed: %v", err)
	}
	shadowPath, err := shadow.Generate(outUnit, models.UnitManifest{PackageName: "devreg_unit", Unit: "device_register"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify Bug #2 (no internal/* imports outside repo) & Bug #5 (no secret leak, x-app-id kept, //go:embed)
	for _, genFile := range []string{scafOut.ClientGen, scafOut.PortPath, filepath.Join(outUnit, "wire_capture_gen_test.go"), shadowPath} {
		data, rerr := os.ReadFile(genFile)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if strings.Contains(string(data), "github.com/TaTrap/request-anything/internal/") {
			t.Fatalf("generated file %s leaked forbidden internal/ import:\n%s", genFile, data)
		}
	}
	if _, serr := os.Stat(filepath.Join(outUnit, "go.mod")); serr != nil {
		t.Fatalf("expected standalone go.mod in external unit dir: %v", serr)
	}
	for _, noLeakFile := range []string{scafOut.FixturePath, scafOut.PortPath, filepath.Join(outUnit, contract.TaskFile)} {
		data, _ := os.ReadFile(noLeakFile)
		if strings.Contains(string(data), "superSecret99") {
			t.Fatalf("secret leaked into %s", noLeakFile)
		}
	}
	portSrc, _ := os.ReadFile(scafOut.PortPath)
	if !strings.Contains(string(portSrc), `"1001"`) || !strings.Contains(string(portSrc), "recordedRequestBody") {
		t.Fatalf("expected x-app-id=1001 kept and binary body loaded via recordedRequestBody in port.go:\n%s", portSrc)
	}
	clientGenSrc, _ := os.ReadFile(scafOut.ClientGen)
	if !strings.Contains(string(clientGenSrc), "//go:embed fixtures/") {
		t.Fatalf("expected //go:embed for gzipped body in client_gen.go:\n%s", clientGenSrc)
	}

	// Bug #1 & #2 & #7: Run MCP `gate` with SkipGoChecks:false OUTSIDE repo (compiles + runs port.go + positive assertions)
	gateRes, err := mcp.CallTool(ctx, "gate", map[string]any{
		"unit":             outUnit,
		"skip_go_checks":   false,
		"include_response": true,
	})
	if err != nil {
		t.Fatalf("external MCP gate failed: %v", err)
	}
	gOut := gateRes.(*models.GateOutcome)
	if !gOut.Passed {
		t.Fatalf("expected external standalone gate PASS, got checks=%+v", gOut.Checks)
	}

	// Break port.go: change POST -> DELETE. diff, gate, and auto MUST all FAIL (no false-green!).
	brokenPort := strings.Replace(string(portSrc), `Method:         "POST"`, `Method:         "DELETE"`, 1)
	if brokenPort == string(portSrc) {
		t.Fatalf("could not locate Method POST in port.go")
	}
	if err := os.WriteFile(scafOut.PortPath, []byte(brokenPort), 0o644); err != nil {
		t.Fatal(err)
	}
	dBroken, err := mcp.CallTool(ctx, "diff", map[string]any{"unit": outUnit})
	if err != nil {
		t.Fatal(err)
	}
	if dr := dBroken.(*models.DiffResult); dr.Passed {
		t.Fatalf("Bug #1 regression: MCP diff falsely passed after mutating POST->DELETE!")
	}
	gBrokenRes, err := mcp.CallTool(ctx, "gate", map[string]any{"unit": outUnit, "skip_go_checks": true})
	if err != nil {
		t.Fatal(err)
	}
	if gBroken := gBrokenRes.(*models.GateOutcome); gBroken.Passed {
		t.Fatalf("Bug #1 regression: MCP gate falsely passed after mutating POST->DELETE!")
	}
	autoOut, err := auto.Run(ctx, auto.Options{UnitDir: outUnit})
	if err != nil || autoOut.Stage == "passed" {
		t.Fatalf("Bug #1 regression: auto.Run failed to catch broken port.go: stage=%v err=%v", autoOut, err)
	}
	// Restore working port.go
	if err := os.WriteFile(scafOut.PortPath, portSrc, 0o644); err != nil {
		t.Fatal(err)
	}

	// Bug #6: BuildPortMap --check clean with *.body.bin, then edit contract.yaml -> stale -> Refresh fixes stale
	pmClean, err := report.BuildPortMap(extRepo, true, true)
	if err != nil || pmClean.Stale != 0 {
		t.Fatalf("Bug #6 regression: map --check reported false stale on fresh scaffold: err=%v pm=%+v", err, pmClean)
	}
	contractPath := filepath.Join(outUnit, contract.FileName)
	cData, _ := os.ReadFile(contractPath)
	_ = os.WriteFile(contractPath, append(cData, []byte("\n# edited-for-freshness-test\n")...), 0o644)
	gStaleRes, _ := mcp.CallTool(ctx, "gate", map[string]any{"unit": outUnit, "skip_go_checks": true})
	if gStale := gStaleRes.(*models.GateOutcome); gStale.Passed {
		t.Fatalf("expected modified contract.yaml to fail recording-freshness")
	}
	if err := scaffold.Refresh(outUnit); err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}
	if pmAfter, err := report.BuildPortMap(extRepo, false, true); err != nil || pmAfter.Stale != 0 {
		t.Fatalf("Bug #6 regression: Refresh did not clear recording-freshness stale state: err=%v pm=%+v", err, pmAfter)
	}

	// Bug #3: Same cookie crumb count (2) but wrong names & values MUST FAIL L2
	cookieDiff := diff.CompareRequests(ctx, "c-val",
		&models.WireRequest{Method: "GET", RawPath: "/", Headers: []models.HeaderKV{{RawName: "cookie", Value: "sessionid=REAL; device_tok=REAL"}}, Transport: models.TransportMeta{CaptureFidelity: models.FidelityLosslessWire, Proto: "HTTP/2"}},
		&models.WireRequest{Method: "GET", RawPath: "/", Headers: []models.HeaderKV{{RawName: "cookie", Value: "sessionid=FAKE; alt_target=WRONG"}}, Transport: models.TransportMeta{CaptureFidelity: models.FidelityLosslessWire, Proto: "HTTP/2"}},
		nil, nil, diff.Options{},
	)
	if cookieDiff.Passed {
		t.Fatalf("Bug #3 regression: differing cookie names/values passed L2 diff!")
	}

	// Bug #4: flow.Runner attaches Oracle.Sign headers onto wire requests + decodes gzip response for branching
	var sawSig atomic.Bool
	flowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signed_step" {
			if r.Header.Get("Signature") != "" && r.Header.Get("X-Signature") != "" && r.Header.Get("X-Timestamp") != "" && r.Header.Get("Content-Md5") != "" {
				sawSig.Store(true)
			}
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			_, _ = zw.Write([]byte(`{"device_id":"7319555","status_code":4029}`))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b.Bytes())
			return
		}
		_, _ = w.Write([]byte(`{"status_code":0,"q":"` + r.URL.RawQuery + `"}`))
	}))
	defer flowSrv.Close()

	flowDir := filepath.Join(extRepo, "signed_flow")
	_ = os.MkdirAll(flowDir, 0o755)
	_ = flow.SaveFlow(flowDir, &flow.FlowSpec{
		Schema:  "request-anything/flow@1",
		Name:    "signed_flow",
		BaseURL: flowSrv.URL,
		Steps: []flow.Step{
			{
				ID: "s1", Name: "signed_step", Endpoint: "s1", Method: "POST", RawPath: "/signed_step",
				RawQuery: "app_id=1001", Body: `{"k":1}`, SignWithOracle: true,
				BranchOn: []flow.BranchRule{{Status: 200, JSONPath: "status_code", Equals: "4029", NextStep: "s2"}},
			},
			{
				ID: "s2", Name: "after_branch", Endpoint: "s2", Method: "GET", RawPath: "/after", RawQuery: "did={{device_id}}",
			},
		},
	})
	fOutAny, err := mcp.CallTool(ctx, "flow_replay", map[string]any{"flow_dir": flowDir})
	if err != nil {
		t.Fatalf("flow_replay with Oracle failed: %v", err)
	}
	fOut := fOutAny.(*flow.FlowOutcome)
	if !fOut.Passed || len(fOut.StepsExecuted) != 2 || !sawSig.Load() {
		t.Fatalf("Bug #4/#7 regression: Oracle signatures missing or gzip branch failed: passed=%v sawSig=%v steps=%+v failures=%v", fOut.Passed, sawSig.Load(), fOut.StepsExecuted, fOut.Failures)
	}

	// Bug #11: Real MeasureAndWriteReport (no hardcoded 25.0ms / 2.0ms = 12.5x) & real compiled fuzz
	card, err := report.MeasureAndWriteReport(ctx, outUnit, "")
	if err != nil {
		t.Fatalf("MeasureAndWriteReport failed: %v", err)
	}
	mdBytes, _ := os.ReadFile(card.MarkdownPath)
	if strings.Contains(string(mdBytes), "25.00 ms") || strings.Contains(string(mdBytes), "12.5x") || !strings.Contains(string(mdBytes), "n/a (not recorded)") {
		t.Fatalf("Bug #11 regression: REPORT.md still has fake numbers:\n%s", mdBytes)
	}
	fuzzOut, err := fuzz.Run(ctx, fuzz.Options{UnitDir: outUnit, Cases: 4, Seed: 77, Keep: "all"})
	if err != nil || fuzzOut.Cases != 4 || fuzzOut.Mismatches != 0 || fuzzOut.Kept != 4 {
		t.Fatalf("Bug #11 regression: real unit fuzz failed: err=%v out=%+v", err, fuzzOut)
	}
}

// Verifies the two edge polish items end-to-end:
//  1. Scaffolding inside an existing external host Go project (with ancestor go.mod) updates the host go.mod/go.sum
//     cleanly and idempotently instead of skipping replace wiring.
//  2. OrderedHeaders.Set preserves original HTTP/1.1 header casing (Signature / X-Signature / X-Timestamp / Content-Md5) when
//     Oracle.Sign returns lowercase header names.
func TestE2E_HostProjectGoModAndHTTP1SignCasing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	hostDir := t.TempDir()
	hostGoMod := filepath.Join(hostDir, "go.mod")
	if err := os.WriteFile(hostGoMod, []byte("module example.com/hostapp\n\ngo 1.27.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	subUnit := filepath.Join(hostDir, "ports", "h1_signed")
	body := []byte(`{"k":1}`)
	rawQuery := "app_id=1001"
	h1Fix := &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     "h1-signed-case",
		Name:   "h1_signed",
		Source: "raw_http1",
		Request: models.WireRequest{
			Schema:    models.SchemaFixture,
			Method:    "POST",
			Scheme:    "https",
			Authority: "api.example.com",
			RawPath:   "/v1/check/",
			RawQuery:  rawQuery,
			Query:     wireclient.ParseRawQuery(rawQuery).Params,
			Headers: []models.HeaderKV{
				{RawName: "Host", Value: "api.example.com"},
				{RawName: "Content-Md5", Value: computeStub(body)},
				{RawName: "X-Timestamp", Value: "1700000000"},
				{RawName: "X-Signature", Value: "sig10001deadbeef"},
				{RawName: "Signature", Value: "placeholder_sig"},
				{RawName: "Content-Type", Value: "application/json"},
				{RawName: "Content-Length", Value: fmt.Sprintf("%d", len(body))},
			},
			Body: models.WireBody{RawBytes: body, Encoding: "raw"},
			Transport: models.TransportMeta{
				CaptureFidelity: models.FidelityLosslessWire,
				CookieWireMode:  models.CookieSingleHeader,
				Proto:           "HTTP/1.1",
			},
		},
	}
	ingest.FinalizeBody(&h1Fix.Request.Body, "application/json")

	if _, err := scaffold.Scaffold(scaffold.Options{
		Root:    hostDir,
		OutDir:  subUnit,
		Fixture: h1Fix,
		Force:   true,
	}); err != nil {
		t.Fatalf("scaffold inside host Go project failed: %v", err)
	}

	// Subunit must share parent hostDir/go.mod rather than creating nested go.mod
	if _, err := os.Stat(filepath.Join(subUnit, "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("expected no nested go.mod inside host Go module")
	}
	// Refresh must remain idempotent on host go.mod (no duplicate replace lines)
	if err := scaffold.Refresh(subUnit); err != nil {
		t.Fatalf("Refresh inside host Go project failed: %v", err)
	}
	gmBytes, err := os.ReadFile(hostGoMod)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(gmBytes), "replace github.com/TaTrap/request-anything =>"); count != 1 {
		t.Fatalf("expected exactly 1 replace directive in host go.mod, got %d:\n%s", count, gmBytes)
	}

	// gate with SkipGoChecks:false compiles & executes port.go against ForceHTTP1Raw + MockOracle (lowercase keys)
	// and MUST PASS L2 strict HTTP/1.1 casing!
	gRes, err := mcp.CallTool(ctx, "gate", map[string]any{
		"unit":           subUnit,
		"skip_go_checks": false,
	})
	if err != nil {
		t.Fatalf("gate inside host Go module failed: %v", err)
	}
	gOut := gRes.(*models.GateOutcome)
	if !gOut.Passed {
		t.Fatalf("expected gate inside host Go module + HTTP/1.1 uppercase signed headers to PASS, checks=%+v", gOut.Checks)
	}
}

func TestRepoRootSecretHygieneClean(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Dir(wd)
	findings, err := redact.AuditRepository(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Fatalf("repository contains forbidden artifacts or unredacted secrets: %+v", findings)
	}
}
