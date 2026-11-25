package ingest

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/redact"
)

func TestIngestCurlHarFridaRawAndSQLite(t *testing.T) {
	// 1. cURL with literal '*', trailing '&', and EscapeSolidus `\/`
	curlCmd := `curl -X POST 'https://api.example.com/v2/feed/?iid=&resolution=1216*2623&' -H 'x-signature: abcd' -H 'Content-Type: application/json' -d '{"url":"https:\/\/v1.example.com\/a"}'`
	fixCurl, err := ParseCurl(curlCmd, "feed_test")
	if err != nil {
		t.Fatal(err)
	}
	if !fixCurl.Request.TrailingAmp || fixCurl.Request.RawQuery != "iid=&resolution=1216*2623&" {
		t.Fatalf("curl query fidelity lost: %+v", fixCurl.Request)
	}
	if !fixCurl.Request.Body.JSONStyle.EscapeSolidus {
		t.Fatalf("expected EscapeSolidus=true detected from curl body")
	}

	// 2. Raw HTTP preserves exact lowercase header
	rawHTTP := []byte("POST /v1/check?k=1& HTTP/1.1\r\nHost: api.example.com\r\nx-custom-lower: val\r\nContent-Length: 2\r\n\r\n{}")
	fixRaw, err := ParseRawHTTP(rawHTTP, "https", "raw_check")
	if err != nil {
		t.Fatal(err)
	}
	if fixRaw.Request.Transport.CaptureFidelity != models.FidelityLosslessWire {
		t.Fatalf("expected lossless_wire")
	}
	if fixRaw.Request.Headers[1].RawName != "x-custom-lower" {
		t.Fatalf("expected exact lowercase header x-custom-lower, got %q", fixRaw.Request.Headers[1].RawName)
	}

	// 3. Flat SQLite capture + Save/Load roundtrip
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "capture.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE flows (method TEXT, url TEXT, request_headers TEXT, request_body BLOB, status INTEGER, response_headers TEXT, response_body BLOB);
	INSERT INTO flows VALUES ('POST', 'https://api.example.com/v1/device/register/?iid=&', '[["cookie","a=1"],["cookie","b=2"]]', '{"password":"secret_pw"}', 200, '[["content-type","application/json"]]', '{"status_code":0}');`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	fixes, err := ParseSQLite(dbPath)
	if err != nil || len(fixes) != 1 {
		t.Fatalf("sqlite parse failed: err=%v len=%d", err, len(fixes))
	}
	if fixes[0].Request.Transport.CookieWireMode != models.CookieH2Crumbs {
		t.Fatalf("expected h2_crumbs for multi-cookie SQLite row, got %s", fixes[0].Request.Transport.CookieWireMode)
	}

	fixDir := filepath.Join(tmp, "fixtures")
	fixPath, _, err := SaveFixture(fixDir, fixes[0], redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFixture(fixPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Request.Body.RawBytes) == `{"password":"secret_pw"}` {
		t.Fatalf("expected password to be redacted on disk!")
	}
}

func TestParseGzipCaptureSQLiteAndTSharkJSONPCAP(t *testing.T) {
	// 1. Gzipped capture_requests SQLite schema
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "captures.sqlite3")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE capture_runs(id INTEGER PRIMARY KEY, started_at_ms INTEGER, ended_at_ms INTEGER, label TEXT);
		CREATE TABLE capture_requests(run_id INTEGER, mode TEXT, key TEXT, ordinal INTEGER, summary TEXT, search TEXT, payload BLOB, PRIMARY KEY(run_id, mode, key));
	`)
	if err != nil {
		t.Fatal(err)
	}

	var gzReq bytes.Buffer
	gw := gzip.NewWriter(&gzReq)
	_, _ = gw.Write([]byte(`{"url":"https:\/\/v1.example.com\/register"}`))
	_ = gw.Close()

	sessJSON, _ := json.Marshal(map[string]any{
		"id":               1,
		"key":              "req-1",
		"scheme":           "https",
		"authority":        "api.example.com",
		"method":           "POST",
		"status_code":      200,
		"url_path":         "/v1/device/register/?app_id=1001&",
		"request_headers":  "x-app-id: 1001\r\ncontent-encoding: gzip\r\ncontent-type: application/json\r\ncookie: a=1\r\ncookie: b=2",
		"request_hex":      hex.EncodeToString(gzReq.Bytes()),
		"response_headers": "content-type: application/json",
		"response_body":    `{"device_id":"731999","install_id":"731888"}`,
	})
	var gzBlob bytes.Buffer
	bw := gzip.NewWriter(&gzBlob)
	_, _ = bw.Write(sessJSON)
	_ = bw.Close()

	_, err = db.Exec(`INSERT INTO capture_requests VALUES (1, 'ebpf', 'req-1', 1, 'POST /v1/device/register/', 'device_register', ?)`, gzBlob.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	capFixes, err := ParseSQLite(dbPath)
	if err != nil || len(capFixes) != 1 {
		t.Fatalf("ParseSQLite gzipped capture failed: err=%v fixes=%d", err, len(capFixes))
	}
	if capFixes[0].Request.Body.Kind != "json" || !capFixes[0].Request.Body.JSONStyle.EscapeSolidus {
		t.Fatalf("expected gzipped capture body decoded into EscapeSolidus json, got %+v", capFixes[0].Request.Body)
	}
	if !capFixes[0].Request.TrailingAmp || capFixes[0].Request.Transport.CookieWireMode != models.CookieH2Crumbs {
		t.Fatalf("expected capture trailing & and h2_crumbs preserved: %+v", capFixes[0].Request)
	}

	// 2. tshark -T json parser (HTTP/2 with cookie crumbs & DATA)
	tsharkJSON := []byte(`[
		{
			"_source": {
				"layers": {
					"tcp": {"tcp.stream": "3"},
					"tls": {"tls.handshake.ja3": "ja3_mock_hash"},
					"http2": [
						{
							"http2.streamid": "1",
							"http2.header.name": [":method", ":scheme", ":authority", ":path", "cookie", "cookie", "content-type"],
							"http2.header.value": ["POST", "https", "api.example.com", "/v2/feed/?iid=&", "sessionid=s1", "device_tok=o1", "application/json"],
							"http2.data.data": "` + hex.EncodeToString([]byte(`{"ok":true}`)) + `"
						},
						{
							"http2.streamid": "1",
							"http2.header.name": [":status", "content-type"],
							"http2.header.value": ["200", "application/json"],
							"http2.data.data": "` + hex.EncodeToString([]byte(`{"status_code":0}`)) + `"
						}
					]
				}
			}
		}
	]`)
	pcapFixes, err := ParseTSharkJSON(tsharkJSON)
	if err != nil || len(pcapFixes) != 1 {
		t.Fatalf("ParseTSharkJSON failed: err=%v len=%d", err, len(pcapFixes))
	}
	pf := pcapFixes[0]
	if pf.Request.Transport.CookieWireMode != models.CookieH2Crumbs || pf.Request.Transport.JA3Hash != "ja3_mock_hash" {
		t.Fatalf("expected h2_crumbs + ja3_mock_hash, got %+v", pf.Request.Transport)
	}
	if pf.Response == nil || pf.Response.Status != 200 {
		t.Fatalf("expected paired H2 response 200, got %+v", pf.Response)
	}
}
