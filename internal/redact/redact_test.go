package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TaTrap/request-anything/internal/models"
)

func TestRedactFixtureAndAudit(t *testing.T) {
	fix := &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     "1",
		Request: models.WireRequest{
			RawQuery:    "app_id=1001&password=hunter2!&",
			TrailingAmp: true,
			Query: []models.QueryParam{
				{RawKey: "app_id", RawValue: "1001", HasEq: true},
				{RawKey: "password", RawValue: "hunter2!", HasEq: true},
			},
			Headers: []models.HeaderKV{
				{RawName: "x-app-id", Value: "1001"},
				{RawName: "Authorization", Value: "Bearer supersecretjwt12345"},
				{RawName: "Cookie", Value: "sessionid=abc999; csrf_tok=ok"},
			},
			Body: models.WireBody{
				RawBytes: []byte(`{"device_private_key":"secret_hex_key_99"}`),
			},
		},
	}

	redacted := RedactFixture(fix, Options{})
	if redacted.Request.Query[1].RawValue == "hunter2!" {
		t.Fatalf("password query param was not redacted")
	}
	if strings.Contains(redacted.Request.RawQuery, "hunter2!") || !strings.HasSuffix(redacted.Request.RawQuery, "&") {
		t.Fatalf("RawQuery was not redacted or lost trailing &: %q", redacted.Request.RawQuery)
	}
	if redacted.Request.Headers[0].Value != "1001" {
		t.Fatalf("public app_id header x-app-id was wrongly redacted: %s", redacted.Request.Headers[0].Value)
	}
	if !strings.HasPrefix(redacted.Request.Query[1].RawValue, "<REDACTED:") {
		t.Fatalf("unexpected redaction token: %s", redacted.Request.Query[1].RawValue)
	}
	if strings.Contains(string(redacted.Request.Body.RawBytes), "secret_hex_key_99") {
		t.Fatalf("device_private_key leaked into redacted body: %s", redacted.Request.Body.RawBytes)
	}
	if !strings.Contains(redacted.Request.Headers[2].Value, "csrf_tok=ok") || strings.Contains(redacted.Request.Headers[2].Value, "abc999") {
		t.Fatalf("cookie redaction broken: %s", redacted.Request.Headers[2].Value)
	}

	// Binary/gzip bytes with invalid UTF-8 must pass through untouched
	binFix := &models.GoldenFixture{
		Request: models.WireRequest{
			Body: models.WireBody{RawBytes: []byte{0x1f, 0x8b, 0x08, 0xff, 0xfe, 0x00}},
		},
	}
	binRed := RedactFixture(binFix, Options{})
	if len(binRed.Request.Body.RawBytes) != 6 || binRed.Request.Body.RawBytes[3] != 0xff {
		t.Fatalf("binary gzip payload was corrupted by ScrubText: %x", binRed.Request.Body.RawBytes)
	}

	tmp := t.TempDir()
	badFile := filepath.Join(tmp, "leak.json")
	if err := os.WriteFile(badFile, []byte("-----BEGIN EC PRIVATE KEY-----\nabc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AuditDirectory(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 || findings[0].Kind != "private_key" {
		t.Fatalf("expected private_key finding, got %+v", findings)
	}
}
