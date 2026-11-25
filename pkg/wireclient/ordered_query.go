package wireclient

import (
	"fmt"
	"strings"

	"github.com/TaTrap/request-anything/pkg/models"
)

// OrderedQuery preserves exact parameter ordering, duplicates, encoding quirks (e.g. `*`), and trailing `&`.
type OrderedQuery struct {
	Params      []models.QueryParam
	TrailingAmp bool
	SpaceAsPlus bool
}

// ParseRawQuery splits a raw query string without decoding or reordering.
func ParseRawQuery(raw string) *OrderedQuery {
	q := &OrderedQuery{}
	if raw == "" {
		return q
	}
	trimmed := raw
	if strings.HasSuffix(trimmed, "&") {
		q.TrailingAmp = true
		trimmed = strings.TrimSuffix(trimmed, "&")
	}
	if trimmed == "" {
		return q
	}
	parts := strings.Split(trimmed, "&")
	for _, seg := range parts {
		if idx := strings.IndexByte(seg, '='); idx >= 0 {
			q.Params = append(q.Params, models.QueryParam{
				RawKey:   seg[:idx],
				RawValue: seg[idx+1:],
				HasEq:    true,
			})
		} else {
			q.Params = append(q.Params, models.QueryParam{
				RawKey: seg,
				HasEq:  false,
			})
		}
	}
	return q
}

// NewOrderedQuery creates a query builder initialized from an existing slice and trailing ampersand flag.
func NewOrderedQuery(params []models.QueryParam, trailingAmp bool) *OrderedQuery {
	cp := make([]models.QueryParam, len(params))
	copy(cp, params)
	return &OrderedQuery{
		Params:      cp,
		TrailingAmp: trailingAmp,
	}
}

// Add appends a query parameter verbatim (Modified=false).
func (q *OrderedQuery) Add(rawKey, rawVal string, hasEq bool) {
	q.Params = append(q.Params, models.QueryParam{
		RawKey:   rawKey,
		RawValue: rawVal,
		HasEq:    hasEq,
		Modified: false,
	})
}

// Set replaces the first matching parameter (marking it Modified=true so it encodes safely) or appends it.
func (q *OrderedQuery) Set(rawKey, val string) {
	for i := range q.Params {
		if q.Params[i].RawKey == rawKey {
			q.Params[i].RawValue = val
			q.Params[i].HasEq = true
			q.Params[i].Modified = true
			return
		}
	}
	q.Params = append(q.Params, models.QueryParam{
		RawKey:   rawKey,
		RawValue: val,
		HasEq:    true,
		Modified: true,
	})
}

// SetRaw replaces the first matching parameter verbatim without re-encoding (Modified=false).
func (q *OrderedQuery) SetRaw(rawKey, rawVal string, hasEq bool) {
	for i := range q.Params {
		if q.Params[i].RawKey == rawKey {
			q.Params[i].RawValue = rawVal
			q.Params[i].HasEq = hasEq
			q.Params[i].Modified = false
			return
		}
	}
	q.Add(rawKey, rawVal, hasEq)
}

// Get returns the raw value of the first matching parameter.
func (q *OrderedQuery) Get(rawKey string) (string, bool) {
	for _, p := range q.Params {
		if p.RawKey == rawKey {
			return p.RawValue, true
		}
	}
	return "", false
}

// Encode serializes query parameters onto the wire.
// Unmodified parameters are written verbatim (preserving `*` in `1216*2623`, `%20` vs `+`, and `iid=`).
func (q *OrderedQuery) Encode() string {
	if q == nil || (len(q.Params) == 0 && !q.TrailingAmp) {
		return ""
	}
	var b strings.Builder
	for i, p := range q.Params {
		if i > 0 {
			b.WriteByte('&')
		}
		k := p.RawKey
		v := p.RawValue
		if p.Modified {
			k = percentEncodeComponent(k, q.SpaceAsPlus)
			v = percentEncodeComponent(v, q.SpaceAsPlus)
		}
		b.WriteString(k)
		if p.HasEq {
			b.WriteByte('=')
			b.WriteString(v)
		}
	}
	if q.TrailingAmp {
		b.WriteByte('&')
	}
	return b.String()
}

// BuildRawRequestURI joins rawPath and encoded query cleanly without path normalization.
func BuildRawRequestURI(rawPath string, q *OrderedQuery) string {
	if rawPath == "" {
		rawPath = "/"
	}
	enc := q.Encode()
	if enc == "" {
		return rawPath
	}
	return rawPath + "?" + enc
}

func percentEncodeComponent(s string, spaceAsPlus bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUnreserved(c):
			b.WriteByte(c)
		case c == ' ' && spaceAsPlus:
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
