package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"github.com/bogdanfinn/tls-client/profiles"
)

func TestLoopbackProxyRawH2CrumbsAndRawH1(t *testing.T) {
	proxy, err := StartLoopbackProxy(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// 1. Test bogdanfinn/tls-client + fhttp + utls over CONNECT + TLS + raw 9-byte H2 + hpack.Decoder
	client, err := wireclient.NewClient(wireclient.ClientOptions{
		Profile:  profiles.Okhttp4Android13,
		ProxyURL: proxy.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}

	hdrs := wireclient.NewOrderedHeaders(nil)
	hdrs.Add("content-md5", "ABC123")
	hdrs.Add("cookie", "sessionid=s1; sid_token=t2")
	hdrs.Add("content-type", "application/json")

	req := &wireclient.OrderedRequest{
		Method:         "POST",
		Scheme:         "https",
		Authority:      "api.example.com",
		RawPath:        "/v2/feed/",
		Query:          wireclient.ParseRawQuery("iid=&resolution=1216*2623&"),
		Headers:        hdrs,
		CookieWireMode: models.CookieH2Crumbs,
		PseudoOrder:    []string{":method", ":path", ":authority", ":scheme"},
		Body:           []byte(`{"url":"https:\/\/v1.example.com\/a"}`),
	}
	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("H2 proxy roundtrip failed: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	caps := proxy.Captured()
	if len(caps) != 1 {
		t.Fatalf("expected 1 captured H2 request, got %d", len(caps))
	}
	got := caps[0]
	if got.Transport.Proto != "HTTP/2" {
		t.Fatalf("expected HTTP/2, got %s", got.Transport.Proto)
	}
	if got.Transport.JA4 == "" || got.Transport.JA3Hash == "" {
		t.Fatalf("expected non-empty JA3/JA4 from ClientHello peek")
	}
	if got.Transport.CookieWireMode != models.CookieH2Crumbs {
		t.Fatalf("expected CookieH2Crumbs on wire, got %s", got.Transport.CookieWireMode)
	}
	if !got.TrailingAmp || got.RawQuery != "iid=&resolution=1216*2623&" {
		t.Fatalf("H2 raw query altered: %+v", got)
	}
	if string(got.Body.RawBytes) != `{"url":"https:\/\/v1.example.com\/a"}` {
		t.Fatalf("body mismatch: %s", got.Body.RawBytes)
	}

	// 2. Test ForceHTTP1Raw preserves exact lowercase header casing
	proxy.Reset()
	hdrsH1 := wireclient.NewOrderedHeaders(nil)
	hdrsH1.Add("Host", "api.example.com")
	hdrsH1.Add("x-signature", "sig10001")
	respH1, err := client.Do(context.Background(), &wireclient.OrderedRequest{
		Method:        "POST",
		Scheme:        "https",
		Authority:     "api.example.com",
		RawPath:       "/v1/check/",
		Query:         wireclient.ParseRawQuery("iid=&"),
		Headers:       hdrsH1,
		Body:          []byte("{}"),
		ForceHTTP1Raw: true,
	})
	if err != nil {
		t.Fatalf("raw HTTP/1.1 failed: %v", err)
	}
	if respH1.Status != 200 {
		t.Fatalf("expected 200 H1, got %d", respH1.Status)
	}
	caps = proxy.Captured()
	if len(caps) != 1 || caps[0].Headers[1].RawName != "x-signature" {
		t.Fatalf("expected exact lowercase x-signature in H1 raw capture, got %+v", caps)
	}

	// 3. Test >16KB H2 response chunking (no FRAME_SIZE_ERROR) and gzipped JSON request decoding
	largePayload := bytes.Repeat([]byte("A"), 48*1024)
	largeProxy, err := StartLoopbackProxy(func(r *models.WireRequest) *models.WireResponse {
		return &models.WireResponse{
			Status:  200,
			Headers: []models.HeaderKV{{RawName: "content-type", Value: "application/octet-stream"}},
			Body:    models.WireBody{RawBytes: largePayload},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer largeProxy.Close()

	largeClient, err := wireclient.NewClient(wireclient.ClientOptions{
		Profile:  profiles.Okhttp4Android13,
		ProxyURL: largeProxy.URL(),
	})
	if err != nil {
		t.Fatal(err)
	}

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte(`{"url":"https:\/\/gz.example.com\/v1"}`))
	_ = gw.Close()

	gzHdrs := wireclient.NewOrderedHeaders([]models.HeaderKV{
		{RawName: "content-encoding", Value: "gzip"},
		{RawName: "content-type", Value: "application/json"},
	})
	respBig, err := largeClient.Do(context.Background(), &wireclient.OrderedRequest{
		Method:    "POST",
		Scheme:    "https",
		Authority: "api.example.com",
		RawPath:   "/large",
		Headers:   gzHdrs,
		Body:      gzBuf.Bytes(),
	})
	if err != nil {
		t.Fatalf("48KB H2 response / gzipped POST failed: %v", err)
	}
	if len(respBig.Body) != len(largePayload) {
		t.Fatalf("expected %d bytes in large H2 response, got %d", len(largePayload), len(respBig.Body))
	}
	gzCaps := largeProxy.Captured()
	if len(gzCaps) != 1 || gzCaps[0].Body.Kind != "json" || !gzCaps[0].Body.JSONStyle.EscapeSolidus {
		t.Fatalf("expected gzipped JSON POST to preserve Kind=json and EscapeSolidus=true, got %+v", gzCaps)
	}
}
