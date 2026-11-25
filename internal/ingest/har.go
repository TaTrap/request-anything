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

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method      string  `json:"method"`
	URL         string  `json:"url"`
	HTTPVersion string  `json:"httpVersion"`
	Headers     []harNV `json:"headers"`
	PostData    *struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	} `json:"postData"`
}

type harResponse struct {
	Status  int     `json:"status"`
	Headers []harNV `json:"headers"`
	Content struct {
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	} `json:"content"`
}

// ParseHAR imports entries from a HAR 1.2 file, marking CaptureFidelity as lossy_har.
func ParseHAR(path string) ([]*models.GoldenFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("parsing HAR %s: %w", path, err)
	}
	out := make([]*models.GoldenFixture, 0, len(har.Log.Entries))
	for i, e := range har.Log.Entries {
		scheme, authority, rawPath, rawQuery := SplitRawURL(e.Request.URL)
		oq := wireclient.ParseRawQuery(rawQuery)
		headers := make([]models.HeaderKV, 0, len(e.Request.Headers))
		cookieCount := 0
		for _, h := range e.Request.Headers {
			if strings.HasPrefix(h.Name, ":") {
				continue // HAR pseudo-headers are unreliable / stripped
			}
			if strings.EqualFold(h.Name, "cookie") {
				cookieCount++
			}
			headers = append(headers, models.HeaderKV{
				RawName: h.Name,
				Value:   h.Value,
			})
		}
		var reqBody []byte
		if e.Request.PostData != nil && e.Request.PostData.Text != "" {
			if strings.EqualFold(e.Request.PostData.Encoding, "base64") {
				dec, err := base64.StdEncoding.DecodeString(e.Request.PostData.Text)
				if err == nil {
					reqBody = dec
				} else {
					reqBody = []byte(e.Request.PostData.Text)
				}
			} else {
				reqBody = []byte(e.Request.PostData.Text)
			}
		}

		proto := "HTTP/1.1"
		if strings.Contains(strings.ToUpper(e.Request.HTTPVersion), "2") {
			proto = "HTTP/2"
		}
		cookieMode := models.CookieSingleHeader
		if cookieCount > 1 {
			cookieMode = models.CookieH2Crumbs
		}

		ct := HeaderValue(headers, "content-type")
		if ct == "" && e.Request.PostData != nil {
			ct = e.Request.PostData.MimeType
		}
		wireReqBody := models.WireBody{
			Encoding: HeaderValue(headers, "content-encoding"),
			RawBytes: reqBody,
		}
		FinalizeBody(&wireReqBody, ct)

		var resp *models.WireResponse
		if e.Response.Status > 0 {
			rHeaders := make([]models.HeaderKV, 0, len(e.Response.Headers))
			for _, h := range e.Response.Headers {
				rHeaders = append(rHeaders, models.HeaderKV{RawName: h.Name, Value: h.Value})
			}
			var rBody []byte
			if e.Response.Content.Text != "" {
				if strings.EqualFold(e.Response.Content.Encoding, "base64") {
					dec, err := base64.StdEncoding.DecodeString(e.Response.Content.Text)
					if err == nil {
						rBody = dec
					} else {
						rBody = []byte(e.Response.Content.Text)
					}
				} else {
					rBody = []byte(e.Response.Content.Text)
				}
			}
			wb := models.WireBody{
				Encoding: HeaderValue(rHeaders, "content-encoding"),
				RawBytes: rBody,
			}
			FinalizeBody(&wb, e.Response.Content.MimeType)
			resp = &models.WireResponse{
				Status:  e.Response.Status,
				Headers: rHeaders,
				Body:    wb,
			}
		}

		name := fmt.Sprintf("har_%03d_%s_%s", i+1, strings.ToLower(e.Request.Method), SafeSlug(rawPath))
		out = append(out, &models.GoldenFixture{
			Schema:    models.SchemaFixture,
			ID:        name,
			Name:      name,
			Source:    "har",
			CreatedAt: e.StartedDateTime,
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      strings.ToUpper(e.Request.Method),
				Scheme:      scheme,
				Authority:   authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     headers,
				Body:        wireReqBody,
				Transport: models.TransportMeta{
					CaptureFidelity: models.FidelityLossyHAR,
					CookieWireMode:  cookieMode,
					Proto:           proto,
				},
			},
			Response: resp,
		})
	}
	return out, nil
}
