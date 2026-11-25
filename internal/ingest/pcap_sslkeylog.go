package ingest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/process"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

type tsharkPacket struct {
	Source struct {
		Layers map[string]any `json:"layers"`
	} `json:"_source"`
}

// ParsePCAPWithSSLKeyLog extracts decrypted HTTP/1.1 & HTTP/2 wire flows from a PCAP using tshark + SSLKEYLOGFILE.
func ParsePCAPWithSSLKeyLog(pcapPath, keylogPath string) ([]*models.GoldenFixture, error) {
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		return nil, fmt.Errorf("tshark not found on PATH; install Wireshark/tshark or convert PCAP to HAR/NDJSON first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	args := []string{"-r", pcapPath, "-Y", "http || http2", "-T", "json"}
	if keylogPath != "" {
		args = append([]string{"-o", "tls.keylog_file:" + keylogPath}, args...)
	}
	out, err := process.Run(ctx, "", 60*time.Second, nil, nil, tshark, args...)
	if err != nil {
		errTxt := ""
		if out != nil {
			errTxt = string(out.Stderr)
		}
		return nil, fmt.Errorf("tshark decode failed: %w (%s)", err, strings.TrimSpace(errTxt))
	}
	if out == nil || len(strings.TrimSpace(string(out.Stdout))) == 0 {
		return nil, fmt.Errorf("no decrypted HTTP/HTTP2 frames found in %s", pcapPath)
	}
	return ParseTSharkJSON(out.Stdout)
}

// ParseTSharkJSON parses `tshark -T json` packet arrays into lossless GoldenFixtures (HTTP/1.1 & HTTP/2).
func ParseTSharkJSON(rawJSON []byte) ([]*models.GoldenFixture, error) {
	var pkts []tsharkPacket
	if err := json.Unmarshal(rawJSON, &pkts); err != nil {
		return nil, fmt.Errorf("parsing tshark -T json output: %w", err)
	}

	type h2StreamAcc struct {
		streamKey   string
		order       int
		method      string
		scheme      string
		authority   string
		rawTarget   string
		reqHeaders  []models.HeaderKV
		pseudoOrder []string
		cookieCount int
		reqBody     []byte
		respStatus  int
		respHeaders []models.HeaderKV
		respBody    []byte
		ja3         string
	}

	var fixtures []*models.GoldenFixture
	h1Pending := make(map[string]*models.GoldenFixture)
	h2Streams := make(map[string]*h2StreamAcc)
	seq := 0

	for _, pkt := range pkts {
		layers := pkt.Source.Layers
		if layers == nil {
			continue
		}
		tcpStream := firstLayerString(layers, "tcp", "tcp.stream")
		if tcpStream == "" {
			tcpStream = "0"
		}
		ja3 := firstLayerString(layers, "tls", "tls.handshake.ja3")

		// Handle HTTP/1.1 layers
		for _, hl := range asLayerMaps(layers["http"]) {
			if method := firstString(hl["http.request.method"]); method != "" {
				method = strings.ToUpper(method)
				fullURI := firstString(hl["http.request.full_uri"])
				host := firstString(hl["http.host"])
				reqURI := firstString(hl["http.request.uri"])
				var scheme, authority, rawPath, rawQuery string
				if fullURI != "" {
					scheme, authority, rawPath, rawQuery = SplitRawURL(fullURI)
				} else {
					scheme = "https"
					authority = host
					if p, q, hasQ := strings.Cut(reqURI, "?"); hasQ {
						rawPath = p
						rawQuery = q
					} else {
						rawPath = reqURI
					}
					if rawPath == "" {
						rawPath = "/"
					}
				}
				headers, _ := parseTSharkHTTPLines(extractStrings(hl["http.request.line"]))
				body := decodeTSharkData(hl["http.file_data"])
				wb := models.WireBody{
					Encoding: HeaderValue(headers, "content-encoding"),
					RawBytes: body,
				}
				FinalizeBody(&wb, HeaderValue(headers, "content-type"))

				oq := wireclient.ParseRawQuery(rawQuery)
				seq++
				name := fmt.Sprintf("pcap_%03d_%s_%s", seq, strings.ToLower(method), SafeSlug(rawPath))
				fix := &models.GoldenFixture{
					Schema: models.SchemaFixture,
					ID:     name,
					Name:   name,
					Source: "pcap",
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
							Proto:           "HTTP/1.1",
							JA3Hash:         ja3,
						},
					},
				}
				fixtures = append(fixtures, fix)
				h1Pending[tcpStream] = fix
			} else if codeStr := firstString(hl["http.response.code"]); codeStr != "" {
				if fix, ok := h1Pending[tcpStream]; ok && fix != nil {
					code, _ := strconv.Atoi(codeStr)
					rHeaders, _ := parseTSharkHTTPLines(extractStrings(hl["http.response.line"]))
					rBody := decodeTSharkData(hl["http.file_data"])
					rwb := models.WireBody{
						Encoding: HeaderValue(rHeaders, "content-encoding"),
						RawBytes: rBody,
					}
					FinalizeBody(&rwb, HeaderValue(rHeaders, "content-type"))
					fix.Response = &models.WireResponse{
						Status:  code,
						Headers: rHeaders,
						Body:    rwb,
					}
				}
			}
		}

		// Handle HTTP/2 layers (each HTTP/2 frame or stream map inside `layers.http2`)
		for _, h2l := range asLayerMaps(layers["http2"]) {
			sid := firstString(h2l["http2.streamid"])
			if sid == "" {
				sid = firstNestedString(h2l, "http2.stream", "http2.streamid")
			}
			if sid == "" || sid == "0" {
				continue
			}
			sKey := tcpStream + ":" + sid
			acc, exists := h2Streams[sKey]
			if !exists {
				seq++
				acc = &h2StreamAcc{streamKey: sKey, order: seq, scheme: "https", ja3: ja3}
				h2Streams[sKey] = acc
			}
			if acc.ja3 == "" && ja3 != "" {
				acc.ja3 = ja3
			}

			names := collectH2HeaderNames(h2l)
			values := collectH2HeaderValues(h2l)
			pairCount := len(names)
			if len(values) < pairCount {
				pairCount = len(values)
			}

			isResp := false
			isReq := false
			for i := 0; i < pairCount; i++ {
				if strings.EqualFold(names[i], ":status") {
					isResp = true
				}
				if strings.EqualFold(names[i], ":method") {
					isReq = true
				}
			}

			for i := 0; i < pairCount; i++ {
				k := names[i]
				v := values[i]
				isPseudo := strings.HasPrefix(k, ":")
				if isResp {
					if k == ":status" {
						acc.respStatus, _ = strconv.Atoi(v)
					} else if !isPseudo {
						acc.respHeaders = append(acc.respHeaders, models.HeaderKV{RawName: k, Value: v})
					}
					continue
				}
				if isReq || acc.respStatus == 0 {
					if isPseudo {
						acc.pseudoOrder = append(acc.pseudoOrder, k)
						switch k {
						case ":method":
							acc.method = strings.ToUpper(v)
						case ":scheme":
							acc.scheme = v
						case ":authority":
							acc.authority = v
						case ":path":
							acc.rawTarget = v
						}
					} else if strings.EqualFold(k, "cookie") {
						acc.cookieCount++
					}
					acc.reqHeaders = append(acc.reqHeaders, models.HeaderKV{
						RawName:  k,
						Value:    v,
						IsPseudo: isPseudo,
					})
				}
			}

			if dataBytes := decodeTSharkData(h2l["http2.data.data"]); len(dataBytes) > 0 {
				if isResp || acc.respStatus > 0 {
					acc.respBody = append(acc.respBody, dataBytes...)
				} else {
					acc.reqBody = append(acc.reqBody, dataBytes...)
				}
			}
		}
	}

	var h2List []*h2StreamAcc
	for _, acc := range h2Streams {
		if acc.method != "" {
			h2List = append(h2List, acc)
		}
	}
	sort.Slice(h2List, func(i, j int) bool { return h2List[i].order < h2List[j].order })

	for _, acc := range h2List {
		rawPath := acc.rawTarget
		rawQuery := ""
		if p, q, hasQ := strings.Cut(acc.rawTarget, "?"); hasQ {
			rawPath = p
			rawQuery = q
		}
		if rawPath == "" {
			rawPath = "/"
		}
		oq := wireclient.ParseRawQuery(rawQuery)
		wb := models.WireBody{
			Encoding: HeaderValue(acc.reqHeaders, "content-encoding"),
			RawBytes: acc.reqBody,
		}
		FinalizeBody(&wb, HeaderValue(acc.reqHeaders, "content-type"))

		cookieMode := models.CookieSingleHeader
		if acc.cookieCount > 1 {
			cookieMode = models.CookieH2Crumbs
		}

		var resp *models.WireResponse
		if acc.respStatus > 0 {
			rwb := models.WireBody{
				Encoding: HeaderValue(acc.respHeaders, "content-encoding"),
				RawBytes: acc.respBody,
			}
			FinalizeBody(&rwb, HeaderValue(acc.respHeaders, "content-type"))
			resp = &models.WireResponse{
				Status:  acc.respStatus,
				Headers: acc.respHeaders,
				Body:    rwb,
			}
		}

		name := fmt.Sprintf("pcap_h2_%03d_%s_%s", acc.order, strings.ToLower(acc.method), SafeSlug(rawPath))
		fixtures = append(fixtures, &models.GoldenFixture{
			Schema: models.SchemaFixture,
			ID:     name,
			Name:   name,
			Source: "pcap",
			Request: models.WireRequest{
				Schema:      models.SchemaFixture,
				Method:      acc.method,
				Scheme:      acc.scheme,
				Authority:   acc.authority,
				RawPath:     rawPath,
				RawQuery:    rawQuery,
				TrailingAmp: oq.TrailingAmp,
				Query:       oq.Params,
				Headers:     acc.reqHeaders,
				Body:        wb,
				Transport: models.TransportMeta{
					CaptureFidelity: models.FidelityLosslessWire,
					CookieWireMode:  cookieMode,
					Proto:           "HTTP/2",
					ALPN:            "h2",
					JA3Hash:         acc.ja3,
					PseudoOrder:     acc.pseudoOrder,
				},
			},
			Response: resp,
		})
	}

	return fixtures, nil
}

func asLayerMaps(v any) []map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		var out []map[string]any
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func firstLayerString(layers map[string]any, layerName, key string) string {
	for _, m := range asLayerMaps(layers[layerName]) {
		if s := firstString(m[key]); s != "" {
			return s
		}
	}
	return ""
}

func firstNestedString(m map[string]any, childKey, leafKey string) string {
	for _, sub := range asLayerMaps(m[childKey]) {
		if s := firstString(sub[leafKey]); s != "" {
			return s
		}
	}
	return ""
}

func firstString(v any) string {
	ss := extractStrings(v)
	if len(ss) > 0 {
		return ss[0]
	}
	return ""
}

func extractStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, item := range x {
			out = append(out, extractStrings(item)...)
		}
		return out
	default:
		return nil
	}
}

func collectH2HeaderNames(h2l map[string]any) []string {
	if ns := extractStrings(h2l["http2.header.name"]); len(ns) > 0 {
		return ns
	}
	var names []string
	for _, hm := range asLayerMaps(h2l["http2.header"]) {
		names = append(names, extractStrings(hm["http2.header.name"])...)
	}
	return names
}

func collectH2HeaderValues(h2l map[string]any) []string {
	if vs := extractStrings(h2l["http2.header.value"]); len(vs) > 0 {
		return vs
	}
	var vals []string
	for _, hm := range asLayerMaps(h2l["http2.header"]) {
		vals = append(vals, extractStrings(hm["http2.header.value"])...)
	}
	return vals
}

func parseTSharkHTTPLines(lines []string) ([]models.HeaderKV, int) {
	var out []models.HeaderKV
	cookies := 0
	for _, raw := range lines {
		trimmed := strings.TrimRight(raw, "\r\n")
		if k, v, ok := strings.Cut(trimmed, ":"); ok {
			name := strings.TrimSpace(k)
			if strings.EqualFold(name, "cookie") {
				cookies++
			}
			out = append(out, models.HeaderKV{
				RawName: name,
				Value:   strings.TrimLeft(v, " \t"),
			})
		}
	}
	return out, cookies
}

func decodeTSharkData(v any) []byte {
	s := firstString(v)
	if s == "" {
		return nil
	}
	clean := strings.NewReplacer(":", "", " ", "", "\n", "", "\r", "").Replace(s)
	if len(clean)%2 == 0 {
		if b, err := hex.DecodeString(clean); err == nil {
			return b
		}
	}
	return []byte(s)
}
