package ingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

type mitmFlowJSON struct {
	ID      string     `json:"id"`
	Method  string     `json:"method"`
	Scheme  string     `json:"scheme"`
	Host    string     `json:"host"`
	Port    int        `json:"port"`
	Path    string     `json:"path"`
	Proto   string     `json:"http_version"`
	Headers [][]string `json:"headers"`
	BodyB64 string     `json:"body_b64"`
	TLS     struct {
		Version string `json:"version"`
		ALPN    string `json:"alpn"`
		JA3     string `json:"ja3"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
	Status      int        `json:"status"`
	RespHeaders [][]string `json:"resp_headers"`
	RespBodyB64 string     `json:"resp_body_b64"`
}

// ParseMITMFile imports a .mitm binary flow file (via python3+mitmproxy exporter if installed) or pre-exported NDJSON.
func ParseMITMFile(path string) ([]*models.GoldenFixture, error) {
	if strings.HasSuffix(strings.ToLower(path), ".json") || strings.HasSuffix(strings.ToLower(path), ".jsonl") || strings.HasSuffix(strings.ToLower(path), ".ndjson") {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return parseMITMJSONLines(raw)
	}
	py := findPythonForMitm()
	if py == "" {
		return nil, fmt.Errorf("reading binary .mitm file %s requires python3 with mitmproxy installed, or pre-export to NDJSON", path)
	}
	script := `
import sys, json, base64
from mitmproxy import io
with open(sys.argv[1], "rb") as f:
    for flow in io.FlowReader(f).stream():
        if not hasattr(flow, "request"):
            continue
        req = flow.request
        hdrs = [[k.decode("latin1"), v.decode("latin1")] for k, v in req.headers.fields]
        obj = {
            "id": flow.id,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "http_version": req.http_version,
            "headers": hdrs,
            "body_b64": base64.b64encode(req.raw_content or b"").decode("ascii"),
        }
        if flow.response:
            obj["status"] = flow.response.status_code
            obj["resp_headers"] = [[k.decode("latin1"), v.decode("latin1")] for k, v in flow.response.headers.fields]
            obj["resp_body_b64"] = base64.b64encode(flow.response.raw_content or b"").decode("ascii")
        print(json.dumps(obj))
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-c", script, path)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mitmproxy python reader failed: %w (%s)", err, errBuf.String())
	}
	return parseMITMJSONLines(out.Bytes())
}

func findPythonForMitm() string {
	for _, bin := range []string{"python3", "python"} {
		if p, err := exec.LookPath(bin); err == nil {
			return p
		}
	}
	return ""
}

func parseMITMJSONLines(raw []byte) ([]*models.GoldenFixture, error) {
	var out []*models.GoldenFixture
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var fl mitmFlowJSON
		if err := json.Unmarshal([]byte(line), &fl); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		rawPath := fl.Path
		var rawQuery string
		if qIdx := strings.IndexByte(fl.Path, '?'); qIdx >= 0 {
			rawPath = fl.Path[:qIdx]
			rawQuery = fl.Path[qIdx+1:]
		}
		oq := wireclient.ParseRawQuery(rawQuery)
		headers := make([]models.HeaderKV, 0, len(fl.Headers))
		cookieCount := 0
		for _, pair := range fl.Headers {
			if len(pair) < 2 {
				continue
			}
			if strings.EqualFold(pair[0], "cookie") {
				cookieCount++
			}
			headers = append(headers, models.HeaderKV{
				RawName:  pair[0],
				Value:    pair[1],
				IsPseudo: strings.HasPrefix(pair[0], ":"),
			})
		}
		body, _ := base64.StdEncoding.DecodeString(fl.BodyB64)
		cookieMode := models.CookieSingleHeader
		if cookieCount > 1 {
			cookieMode = models.CookieH2Crumbs
		}
		wb := models.WireBody{
			Encoding: HeaderValue(headers, "content-encoding"),
			RawBytes: body,
		}
		FinalizeBody(&wb, HeaderValue(headers, "content-type"))

		var resp *models.WireResponse
		if fl.Status > 0 {
			rHeaders := make([]models.HeaderKV, 0, len(fl.RespHeaders))
			for _, pair := range fl.RespHeaders {
				if len(pair) >= 2 {
					rHeaders = append(rHeaders, models.HeaderKV{RawName: pair[0], Value: pair[1]})
				}
			}
			rBody, _ := base64.StdEncoding.DecodeString(fl.RespBodyB64)
			rwb := models.WireBody{Encoding: HeaderValue(rHeaders, "content-encoding"), RawBytes: rBody}
			FinalizeBody(&rwb, HeaderValue(rHeaders, "content-type"))
			resp = &models.WireResponse{Status: fl.Status, Headers: rHeaders, Body: rwb}
		}

		name := fmt.Sprintf("mitm_%03d_%s_%s", i+1, strings.ToLower(fl.Method), SafeSlug(rawPath))
		out = append(out, &models.GoldenFixture{
			Schema: models.SchemaFixture,
			ID:     SafeSlug(fl.ID + "_" + name),
			Name:   name,
			Source: "mitm",
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      strings.ToUpper(fl.Method),
				Scheme:      fl.Scheme,
				Authority:   fl.Host,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     headers,
				Body:        wb,
				Transport: models.TransportMeta{
					CaptureFidelity: models.FidelityLosslessWire,
					CookieWireMode:  cookieMode,
					Proto:           fl.Proto,
					TLSVersion:      fl.TLS.Version,
					ALPN:            fl.TLS.ALPN,
					JA3Hash:         fl.TLS.JA3,
					JA4:             fl.TLS.JA4,
				},
			},
			Response: resp,
		})
	}
	return out, nil
}
