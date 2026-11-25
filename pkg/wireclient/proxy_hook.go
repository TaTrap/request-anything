package wireclient

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"strings"

	"github.com/TaTrap/request-anything/pkg/models"
)

const (
	EnvDiffProxy      = "REQUEST_ANYTHING_DIFF_PROXY"
	EnvMode           = "REQUEST_ANYTHING_MODE"
	EnvEndpointPrefix = "REQUEST_ANYTHING_EP_"
)

// OrderedRequest holds exact wire-level fields to transmit over HTTP/1.1 or HTTP/2.
type OrderedRequest struct {
	Method         string
	Scheme         string
	Authority      string
	RawPath        string
	Query          *OrderedQuery
	Headers        *OrderedHeaders
	CookieWireMode models.CookieWireMode
	PseudoOrder    []string
	Body           []byte
	ForceHTTP1Raw  bool // Writes raw HTTP/1.1 wire bytes preserving exact non-canonical header casing
}

// RawResponse captures raw response status, ordered headers, and body bytes.
type RawResponse struct {
	Status  int
	Proto   string
	Headers []models.HeaderKV
	Body    []byte
}

// DiffProxyURL returns the loopback diff proxy address if active.
func DiffProxyURL() string {
	return strings.TrimSpace(os.Getenv(EnvDiffProxy))
}

// ShouldUseOriginal checks kill switches REQUEST_ANYTHING_MODE=old or REQUEST_ANYTHING_EP_<NAME>=original.
func ShouldUseOriginal(endpoint string) bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(EnvMode)), "old") {
		return true
	}
	if endpoint == "" {
		return false
	}
	envKey := EnvEndpointPrefix + sanitizeEnvSuffix(endpoint)
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envKey)), "original")
}

func sanitizeEnvSuffix(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ComputeBodyMD5 returns the uppercase MD5 hex digest of the raw request body.
func ComputeBodyMD5(body []byte) string {
	sum := md5.Sum(body)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
