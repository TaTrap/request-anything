package ingest

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// ParseRawHTTP parses a raw HTTP/1.1 request wire capture preserving exact header casing and order.
func ParseRawHTTP(raw []byte, scheme, name string) (*models.GoldenFixture, error) {
	if scheme == "" {
		scheme = "https"
	}
	sep := []byte("\r\n\r\n")
	lineSep := "\r\n"
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		sep = []byte("\n\n")
		lineSep = "\n"
		idx = bytes.Index(raw, sep)
	}
	var headBytes, bodyBytes []byte
	if idx >= 0 {
		headBytes = raw[:idx]
		bodyBytes = raw[idx+len(sep):]
	} else {
		headBytes = raw
	}

	lines := strings.Split(string(headBytes), lineSep)
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty raw HTTP request")
	}
	reqParts := strings.SplitN(strings.TrimSpace(lines[0]), " ", 3)
	if len(reqParts) < 2 {
		return nil, fmt.Errorf("invalid request line %q", lines[0])
	}
	method := strings.ToUpper(reqParts[0])
	target := reqParts[1]
	proto := "HTTP/1.1"
	if len(reqParts) == 3 && reqParts[2] != "" {
		proto = strings.TrimSpace(reqParts[2])
	}

	var headers []models.HeaderKV
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers = append(headers, models.HeaderKV{
			RawName: k,
			Value:   strings.TrimLeft(v, " \t"),
		})
	}

	authority := HeaderValue(headers, "host")
	var rawPath, rawQuery string
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		var s string
		s, authority, rawPath, rawQuery = SplitRawURL(target)
		scheme = s
	} else if qIdx := strings.IndexByte(target, '?'); qIdx >= 0 {
		rawPath = target[:qIdx]
		rawQuery = target[qIdx+1:]
	} else {
		rawPath = target
	}
	if rawPath == "" {
		rawPath = "/"
	}

	if strings.Contains(strings.ToLower(HeaderValue(headers, "transfer-encoding")), "chunked") {
		if decodedChunked, err := decodeChunkedBody(bodyBytes); err == nil {
			bodyBytes = decodedChunked
		}
	} else if cl := HeaderValue(headers, "content-length"); cl != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(cl)); err == nil && n >= 0 && n <= len(bodyBytes) {
			bodyBytes = bodyBytes[:n]
		}
	}

	oq := wireclient.ParseRawQuery(rawQuery)
	if name == "" {
		name = strings.ToLower(method) + "_" + SafeSlug(rawPath)
	}
	wb := models.WireBody{
		Encoding: HeaderValue(headers, "content-encoding"),
		RawBytes: append([]byte(nil), bodyBytes...),
	}
	FinalizeBody(&wb, HeaderValue(headers, "content-type"))

	return &models.GoldenFixture{
		Schema: models.SchemaFixture,
		ID:     SafeSlug(name),
		Name:   name,
		Source: "raw_http",
		Request: models.WireRequest{
			Schema:      models.SchemaFixture,
			Method:      method,
			Scheme:      scheme,
			Authority:   authority,
			RawPath:     rawPath,
			RawQuery:    rawQuery,
			TrailingAmp: oq.TrailingAmp,
			Query:       oq.Params,
			Headers:     headers,
			Body:        wb,
			Transport: models.TransportMeta{
				CaptureFidelity: models.FidelityLosslessWire,
				CookieWireMode:  models.CookieSingleHeader,
				Proto:           proto,
			},
		},
	}, nil
}

func decodeChunkedBody(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	r := bytes.NewReader(raw)
	for {
		line, err := readLineCRLF(r)
		if err != nil {
			return nil, err
		}
		sizeStr, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return out.Bytes(), nil
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		out.Write(chunk)
		_, _ = readLineCRLF(r)
	}
}

func readLineCRLF(r *bytes.Reader) (string, error) {
	var b bytes.Buffer
	for {
		ch, err := r.ReadByte()
		if err != nil {
			return b.String(), err
		}
		if ch == '\n' {
			return strings.TrimSuffix(b.String(), "\r"), nil
		}
		b.WriteByte(ch)
	}
}
