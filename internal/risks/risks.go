package risks

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
)

// Risk describes a protocol/wire subtlety where naive AI ports commonly diverge.
type Risk struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // high | medium | low
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Guidance string `json:"guidance"`
}

// AnalyzeFixture inspects a GoldenFixture and returns detected wire porting risks.
func AnalyzeFixture(f *models.GoldenFixture) []Risk {
	if f == nil {
		return nil
	}
	var out []Risk
	seen := make(map[string]bool)
	add := func(r Risk) {
		if !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r)
		}
	}

	req := f.Request
	if req.TrailingAmp || strings.Contains(req.RawQuery, "*") || strings.Contains(req.RawQuery, "%20") {
		add(Risk{
			ID:       "non_standard_query",
			Severity: "high",
			Title:    "Non-standard raw query formatting (*, trailing &, %20)",
			Detail:   req.RawQuery,
			Guidance: "Use wireclient.OrderedQuery verbatim passthrough; never pass through net/url.Values.Encode().",
		})
	}
	for _, q := range req.Query {
		if q.HasEq && q.RawValue == "" {
			add(Risk{
				ID:       "empty_param_has_eq",
				Severity: "medium",
				Title:    "Empty query parameter with explicit `=` (" + q.RawKey + "=)",
				Detail:   q.RawKey + "=",
				Guidance: "Keep QueryParam.HasEq=true so `?iid=` does not collapse into `?iid` or get dropped.",
			})
		}
		if q.RawKey == "ts" || q.RawKey == "req_ts" || q.RawKey == "nonce" {
			add(Risk{
				ID:       "clock_and_nonce",
				Severity: "medium",
				Title:    "Clock / timestamp / nonce parameter (" + q.RawKey + ")",
				Detail:   q.RawKey + "=" + q.RawValue,
				Guidance: "Declare dynamic regex rule in contract.yaml or use pinned_gen/virtualized sidecar.",
			})
		}
	}

	var bodyMD5Hex string
	if len(req.Body.RawBytes) > 0 {
		sum := md5.Sum(req.Body.RawBytes)
		bodyMD5Hex = hex.EncodeToString(sum[:])
	}

	cookieCount := 0
	for _, h := range req.Headers {
		low := strings.ToLower(h.RawName)
		if low == "cookie" {
			cookieCount++
		}
		if low == "signature" || low == "x-signature" || low == "content-md5" || strings.HasSuffix(low, "-signature") || strings.HasSuffix(low, "-sig") || (bodyMD5Hex != "" && strings.EqualFold(strings.TrimSpace(h.Value), bodyMD5Hex)) {
			add(Risk{
				ID:       "antibot_signature",
				Severity: "high",
				Title:    "Anti-bot native signature header (" + h.RawName + ")",
				Detail:   h.RawName,
				Guidance: "Use NativeOracle RPC sidecar + oracle_verify claims in contract.yaml instead of blind byte equality.",
			})
		}
		if strings.EqualFold(req.Transport.Proto, "HTTP/1.1") && h.RawName != canonicalHTTP1(h.RawName) {
			add(Risk{
				ID:       "http1_header_casing",
				Severity: "medium",
				Title:    "Non-canonical HTTP/1.1 header casing (" + h.RawName + ")",
				Detail:   h.RawName,
				Guidance: "Enable ForceHTTP1Raw on wireclient.OrderedRequest so net/http does not title-case headers.",
			})
		}
	}
	if cookieCount > 1 || req.Transport.CookieWireMode == models.CookieH2Crumbs {
		add(Risk{
			ID:       "cronet_h2_crumbs",
			Severity: "high",
			Title:    "Cronet HTTP/2 separate cookie crumbs",
			Detail:   "cookie_wire_mode=h2_crumbs",
			Guidance: "Set CookieWireMode=h2_crumbs on wireclient.OrderedRequest; do not join into a single Cookie header.",
		})
	}
	if req.Body.Kind == "protobuf" {
		add(Risk{
			ID:       "protobuf_wire_body",
			Severity: "high",
			Title:    "Schema-less Protobuf binary body",
			Detail:   req.Body.BinFile,
			Guidance: "Verify every varint/bytes/nested tag using protowire diff; never cast binary body to UTF-8 string.",
		})
	}
	if req.Body.JSONStyle.EscapeSolidus || bytes.Contains(req.Body.RawBytes, []byte(`\/`)) {
		add(Risk{
			ID:       "json_escape_solidus",
			Severity: "high",
			Title:    "Android JSONObject escaped solidus (`\\/`)",
			Detail:   "breaks body MD5 digest & Content-Length if unescaped",
			Guidance: "Use wireclient.MarshalOrdered with JSONMarshalOptions{EscapeSolidus: true}.",
		})
	}
	if req.Transport.CaptureFidelity == models.FidelityLossyHAR {
		add(Risk{
			ID:       "lossy_har_source",
			Severity: "low",
			Title:    "Capture imported from lossy HAR",
			Detail:   "L2 pseudo-order and L5 TLS/H2 will be reported as unknown",
			Guidance: "Re-capture with loopback/MITM proxy or PCAP+SSLKEYLOG for lossless transport verification.",
		})
	}
	return out
}

func canonicalHTTP1(s string) string {
	parts := strings.Split(strings.ToLower(s), "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}
