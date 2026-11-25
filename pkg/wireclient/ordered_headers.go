package wireclient

import (
	"strings"

	"github.com/TaTrap/request-anything/pkg/models"
	fhttp "github.com/bogdanfinn/fhttp"
)

// OrderedHeaders keeps exact wire header sequence, casing, and Cronet HTTP/2 cookie crumbs.
type OrderedHeaders struct {
	Items []models.HeaderKV
}

// NewOrderedHeaders clones a header slice.
func NewOrderedHeaders(items []models.HeaderKV) *OrderedHeaders {
	cp := make([]models.HeaderKV, len(items))
	copy(cp, items)
	return &OrderedHeaders{Items: cp}
}

// Add appends a header without altering name casing.
func (h *OrderedHeaders) Add(rawName, val string) {
	h.Items = append(h.Items, models.HeaderKV{
		RawName:  rawName,
		Value:    val,
		IsPseudo: strings.HasPrefix(rawName, ":"),
	})
}

// Set replaces the first case-insensitive matching header's value in-place while preserving its original wire casing,
// or appends a new header if absent.
func (h *OrderedHeaders) Set(rawName, val string) {
	for i := range h.Items {
		if strings.EqualFold(h.Items[i].RawName, rawName) {
			h.Items[i].Value = val
			return
		}
	}
	h.Add(rawName, val)
}

// SetWithCasing replaces both the header name casing and value of the first case-insensitive match, or appends it.
func (h *OrderedHeaders) SetWithCasing(rawName, val string) {
	for i := range h.Items {
		if strings.EqualFold(h.Items[i].RawName, rawName) {
			h.Items[i].RawName = rawName
			h.Items[i].Value = val
			return
		}
	}
	h.Add(rawName, val)
}

// Get returns the first matching header value (case-insensitive lookup).
func (h *OrderedHeaders) Get(name string) (string, bool) {
	for _, kv := range h.Items {
		if strings.EqualFold(kv.RawName, name) {
			return kv.Value, true
		}
	}
	return "", false
}

// GetAll returns all values for a given header name in wire order.
func (h *OrderedHeaders) GetAll(name string) []string {
	var out []string
	for _, kv := range h.Items {
		if strings.EqualFold(kv.RawName, name) {
			out = append(out, kv.Value)
		}
	}
	return out
}

// SplitCookieCrumbs splits a joined `a=1; b=2` cookie string into separate crumbs.
func SplitCookieCrumbs(cookie string) []string {
	rawParts := strings.Split(cookie, ";")
	out := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ApplyCookieMode transforms cookie headers in-place between single_header and Cronet h2_crumbs.
func (h *OrderedHeaders) ApplyCookieMode(mode models.CookieWireMode) {
	if mode == "" {
		return
	}
	if mode == models.CookieH2Crumbs {
		var rebuilt []models.HeaderKV
		for _, kv := range h.Items {
			if strings.EqualFold(kv.RawName, "cookie") {
				crumbs := SplitCookieCrumbs(kv.Value)
				if len(crumbs) == 0 {
					rebuilt = append(rebuilt, kv)
					continue
				}
				for _, c := range crumbs {
					rebuilt = append(rebuilt, models.HeaderKV{
						RawName: strings.ToLower(kv.RawName),
						Value:   c,
					})
				}
				continue
			}
			rebuilt = append(rebuilt, kv)
		}
		h.Items = rebuilt
		return
	}

	if mode == models.CookieSingleHeader {
		var crumbs []string
		firstIdx := -1
		var rebuilt []models.HeaderKV
		for _, kv := range h.Items {
			if strings.EqualFold(kv.RawName, "cookie") {
				if firstIdx == -1 {
					firstIdx = len(rebuilt)
					rebuilt = append(rebuilt, kv)
				}
				crumbs = append(crumbs, SplitCookieCrumbs(kv.Value)...)
				continue
			}
			rebuilt = append(rebuilt, kv)
		}
		if firstIdx >= 0 {
			rebuilt[firstIdx].Value = strings.Join(crumbs, "; ")
		}
		h.Items = rebuilt
	}
}

// ToFHTTPHeaders converts OrderedHeaders into bogdanfinn/fhttp Header preserving HeaderOrderKey and PHeaderOrderKey.
func (h *OrderedHeaders) ToFHTTPHeaders(pseudoOrder []string) fhttp.Header {
	hdr := make(fhttp.Header)
	order := make([]string, 0, len(h.Items))
	pOrder := make([]string, 0, 4)
	seenRegular := make(map[string]bool)
	seenPseudo := make(map[string]bool)

	for _, kv := range h.Items {
		if kv.IsPseudo || strings.HasPrefix(kv.RawName, ":") {
			name := strings.ToLower(kv.RawName)
			if !seenPseudo[name] {
				pOrder = append(pOrder, name)
				seenPseudo[name] = true
			}
			continue
		}
		key := strings.ToLower(kv.RawName)
		hdr[key] = append(hdr[key], kv.Value)
		if !seenRegular[key] {
			order = append(order, key)
			seenRegular[key] = true
		}
	}
	if len(pseudoOrder) > 0 {
		pOrder = append([]string(nil), pseudoOrder...)
	}
	if len(pOrder) > 0 {
		hdr[fhttp.PHeaderOrderKey] = pOrder
	}
	if len(order) > 0 {
		hdr[fhttp.HeaderOrderKey] = order
	}
	// Suppress Go/fhttp auto-injected "User-Agent: Go-http-client/*" in both H1 and H2 when caller did not provide one.
	if !seenRegular["user-agent"] {
		hdr["user-agent"] = []string{""}
	}
	return hdr
}
