package ingest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

type fridaHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type fridaDump struct {
	Name           string          `json:"name"`
	Method         string          `json:"method"`
	URL            string          `json:"url"`
	Proto          string          `json:"proto"`
	CookieWireMode string          `json:"cookie_wire_mode"`
	Headers        []fridaHeader   `json:"headers"`
	HeadersMap     json.RawMessage `json:"headers_map,omitempty"`
	BodyB64        string          `json:"body_b64"`
	BodyText       string          `json:"body_text"`
	Status         int             `json:"status"`
	RespHeaders    []fridaHeader   `json:"response_headers"`
	RespBodyB64    string          `json:"response_body_b64"`
	RespBodyText   string          `json:"response_body_text"`
}

// ParseFridaJSON imports a Frida hook dump (or NDJSON list of hook dumps) preserving header order and raw bytes.
func ParseFridaJSON(path string) ([]*models.GoldenFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	var dumps []fridaDump
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &dumps); err != nil {
			return nil, fmt.Errorf("parsing Frida JSON array %s: %w", path, err)
		}
	} else {
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var d fridaDump
			if err := json.Unmarshal([]byte(line), &d); err != nil {
				return nil, fmt.Errorf("parsing Frida JSON line in %s: %w", path, err)
			}
			dumps = append(dumps, d)
		}
	}
	out := make([]*models.GoldenFixture, 0, len(dumps))
	for i, d := range dumps {
		scheme, authority, rawPath, rawQuery := SplitRawURL(d.URL)
		oq := wireclient.ParseRawQuery(rawQuery)
		headers := make([]models.HeaderKV, 0, len(d.Headers))
		cookieCount := 0
		for _, h := range d.Headers {
			if strings.EqualFold(h.Name, "cookie") {
				cookieCount++
			}
			headers = append(headers, models.HeaderKV{
				RawName:  h.Name,
				Value:    h.Value,
				IsPseudo: strings.HasPrefix(h.Name, ":"),
			})
		}
		if len(headers) == 0 && len(d.HeadersMap) > 0 {
			if val, err := wireclient.UnmarshalOrdered(d.HeadersMap); err == nil {
				if om, ok := val.(*wireclient.OrderedMap); ok {
					for _, p := range om.Pairs {
						headers = append(headers, models.HeaderKV{RawName: p.Key, Value: fmt.Sprint(p.Value)})
					}
				}
			}
		}
		var bodyBytes []byte
		if d.BodyB64 != "" {
			bodyBytes, err = base64.StdEncoding.DecodeString(d.BodyB64)
			if err != nil {
				return nil, fmt.Errorf("invalid body_b64 in %s[%d]: %w", path, i, err)
			}
		} else if d.BodyText != "" {
			bodyBytes = []byte(d.BodyText)
		}
		proto := d.Proto
		if proto == "" {
			proto = "HTTP/2"
		}
		cookieMode := models.CookieWireMode(d.CookieWireMode)
		if cookieMode == "" {
			if proto == "HTTP/2" && cookieCount > 1 {
				cookieMode = models.CookieH2Crumbs
			} else {
				cookieMode = models.CookieSingleHeader
			}
		}
		wb := models.WireBody{
			Encoding: HeaderValue(headers, "content-encoding"),
			RawBytes: bodyBytes,
		}
		FinalizeBody(&wb, HeaderValue(headers, "content-type"))

		var resp *models.WireResponse
		if d.Status > 0 {
			rHeaders := make([]models.HeaderKV, 0, len(d.RespHeaders))
			for _, h := range d.RespHeaders {
				rHeaders = append(rHeaders, models.HeaderKV{RawName: h.Name, Value: h.Value})
			}
			var rBody []byte
			if d.RespBodyB64 != "" {
				rBody, _ = base64.StdEncoding.DecodeString(d.RespBodyB64)
			} else if d.RespBodyText != "" {
				rBody = []byte(d.RespBodyText)
			}
			rwb := models.WireBody{Encoding: HeaderValue(rHeaders, "content-encoding"), RawBytes: rBody}
			FinalizeBody(&rwb, HeaderValue(rHeaders, "content-type"))
			resp = &models.WireResponse{Status: d.Status, Headers: rHeaders, Body: rwb}
		}

		name := d.Name
		if name == "" {
			name = fmt.Sprintf("frida_%03d_%s_%s", i+1, strings.ToLower(d.Method), SafeSlug(rawPath))
		}
		out = append(out, &models.GoldenFixture{
			Schema: models.SchemaFixture,
			ID:     SafeSlug(name),
			Name:   name,
			Source: "frida",
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      strings.ToUpper(d.Method),
				Scheme:      scheme,
				Authority:   authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     headers,
				Body:        wb,
				Transport: models.TransportMeta{
					CaptureFidelity: models.FidelityHookDump,
					CookieWireMode:  cookieMode,
					Proto:           proto,
				},
			},
			Response: resp,
		})
	}
	return out, nil
}
