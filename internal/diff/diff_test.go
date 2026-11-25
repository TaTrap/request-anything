package diff

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestSixLayerDiffCatchesMicroDetailsAndReportsUnknowns(t *testing.T) {
	ctx := context.Background()

	// Build raw protobuf: tag 1 varint 100, tag 2 string "ok"
	var p1, p2 []byte
	p1 = protowire.AppendTag(p1, 1, protowire.VarintType)
	p1 = protowire.AppendVarint(p1, 100)
	p1 = protowire.AppendTag(p1, 2, protowire.BytesType)
	p1 = protowire.AppendString(p1, "ok")

	p2 = protowire.AppendTag(p2, 1, protowire.VarintType)
	p2 = protowire.AppendVarint(p2, 101) // 1 varint off
	p2 = protowire.AppendTag(p2, 2, protowire.BytesType)
	p2 = protowire.AppendString(p2, "ok")

	exp := &models.WireRequest{
		Method:      "POST",
		RawPath:     "/v2/feed/",
		RawQuery:    "iid=&resolution=1216*2623&",
		TrailingAmp: true,
		Query:       wireclient.ParseRawQuery("iid=&resolution=1216*2623&").Params,
		Headers: []models.HeaderKV{
			{RawName: "x-signature", Value: "1"},
			{RawName: "cookie", Value: "a=1"},
			{RawName: "cookie", Value: "b=2"},
		},
		Body: models.WireBody{Kind: "protobuf", RawBytes: p1},
		Transport: models.TransportMeta{
			CaptureFidelity: models.FidelityLosslessWire,
			CookieWireMode:  models.CookieH2Crumbs,
			Proto:           "HTTP/1.1",
			PseudoOrder:     []string{":method", ":authority", ":scheme", ":path"},
		},
	}

	act := &models.WireRequest{
		Method:      "POST",
		RawPath:     "/v2/feed/",
		RawQuery:    "iid&resolution=1216%2A2623", // missing HasEq, encoded `*`, missing trailing `&`
		TrailingAmp: false,
		Query:       wireclient.ParseRawQuery("iid&resolution=1216%2A2623").Params,
		Headers: []models.HeaderKV{
			{RawName: "X-Signature", Value: "1"}, // wrong HTTP/1.1 casing
			{RawName: "cookie", Value: "a=1; b=2"},
		},
		Body: models.WireBody{Kind: "protobuf", RawBytes: p2},
		Transport: models.TransportMeta{
			CaptureFidelity: models.FidelityLosslessWire,
			CookieWireMode:  models.CookieSingleHeader,
			Proto:           "HTTP/1.1",
			PseudoOrder:     []string{":method", ":path", ":authority", ":scheme"},
		},
	}

	res := CompareRequests(ctx, "c1", exp, act, nil, nil, Options{StrictTransport: true})
	if res.Passed {
		t.Fatalf("expected multi-layer failure, got PASS")
	}
	wantKinds := map[string]bool{
		"trailing_amp_mismatch":    false,
		"query_has_eq_mismatch":    false,
		"query_value_mismatch":     false,
		"h2_pseudo_order_mismatch": false,
		"cookie_crumbs_joined":     false,
		"header_casing_mismatch":   false,
		"protobuf_varint_mismatch": false,
	}
	for _, f := range res.Findings {
		if _, tracked := wantKinds[f.Kind]; tracked {
			wantKinds[f.Kind] = true
		}
	}
	for k, hit := range wantKinds {
		if !hit {
			t.Fatalf("diff engine missed micro detail %q; findings=%+v", k, res.Findings)
		}
	}
	if len(res.Unknowns) == 0 {
		t.Fatalf("expected explicit Coverage Honesty unknowns for HPACK/QPACK")
	}

	// Verify lossy_har emits L2/L5 unknowns instead of false failures
	expHar := *exp
	expHar.Transport.CaptureFidelity = models.FidelityLossyHAR
	expHar.Transport.Proto = "HTTP/2"
	expHar.Headers = []models.HeaderKV{{RawName: "x-signature", Value: "1"}}
	expHar.Body = models.WireBody{Kind: "json", JSONStyle: models.JSONStyle{EscapeSolidus: true}, RawBytes: []byte(`{"u":"https:\/\/a"}`)}
	actHar := expHar
	resHar := CompareRequests(ctx, "har1", &expHar, &actHar, nil, nil, Options{})
	if !resHar.Passed {
		t.Fatalf("expected matching lossy_har to pass, got %+v", resHar.Findings)
	}
	hasHarUnknown := false
	for _, u := range resHar.Unknowns {
		if u.Kind == "lossy_har_coverage_gap" {
			hasHarUnknown = true
		}
	}
	if !hasHarUnknown {
		t.Fatalf("expected lossy_har_coverage_gap unknown, got %+v", resHar.Unknowns)
	}
}

// Check JSON `\/` EscapeSolidus + `3` vs `3.0` + `1` vs `"1"`
func TestDiffJSONSolidusAndTypes(t *testing.T) {
	ctx := context.Background()
	exp := &models.WireRequest{
		Method: "POST", RawPath: "/",
		Body:      models.WireBody{Kind: "json", JSONStyle: models.JSONStyle{EscapeSolidus: true}, RawBytes: []byte(`{"url":"https:\/\/a","n":3,"s":"1"}`)},
		Transport: models.TransportMeta{CaptureFidelity: models.FidelityHookDump, Proto: "HTTP/2"},
	}
	act := &models.WireRequest{
		Method: "POST", RawPath: "/",
		Body:      models.WireBody{Kind: "json", RawBytes: []byte(`{"url":"https://a","n":3.0,"s":1}`)},
		Transport: models.TransportMeta{CaptureFidelity: models.FidelityHookDump, Proto: "HTTP/2"},
	}
	res := CompareRequests(ctx, "json1", exp, act, nil, nil, Options{})
	if res.Passed {
		t.Fatalf("expected failure on EscapeSolidus, 3 vs 3.0, and \"1\" vs 1")
	}
	if len(res.Findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %+v", res.Findings)
	}
}

func TestL2CookieContentMismatchAndL6GzipResponse(t *testing.T) {
	ctx := context.Background()
	exp := &models.WireRequest{
		Method: "GET", RawPath: "/",
		Headers:   []models.HeaderKV{{RawName: "cookie", Value: "sessionid=REAL; device_tok=REAL"}},
		Transport: models.TransportMeta{CaptureFidelity: models.FidelityLosslessWire, Proto: "HTTP/2"},
	}
	act := &models.WireRequest{
		Method: "GET", RawPath: "/",
		Headers:   []models.HeaderKV{{RawName: "cookie", Value: "sessionid=FAKE; alt_target=WRONG"}},
		Transport: models.TransportMeta{CaptureFidelity: models.FidelityLosslessWire, Proto: "HTTP/2"},
	}
	res := CompareRequests(ctx, "cookie-content", exp, act, nil, nil, Options{})
	if res.Passed {
		t.Fatalf("expected same-count wrong cookie name/value to FAIL L2 diff")
	}

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write([]byte(`{"status_code":0,"msg":"ok"}`))
	_ = gw.Close()

	expResp := &models.WireResponse{Status: 200, Body: models.WireBody{RawBytes: []byte(`{"status_code":0,"msg":"ok"}`)}}
	actResp := &models.WireResponse{
		Status:  200,
		Headers: []models.HeaderKV{{RawName: "content-encoding", Value: "gzip"}},
		Body:    models.WireBody{RawBytes: gz.Bytes(), Encoding: "gzip"},
	}
	l6 := CompareRequests(ctx, "l6-gzip", exp, exp, expResp, actResp, Options{IncludeResponse: true})
	if !l6.Passed {
		t.Fatalf("expected L6 gzip response parity to PASS, got %+v", l6.Findings)
	}
}
