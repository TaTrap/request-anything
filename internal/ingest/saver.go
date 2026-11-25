package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/redact"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// FinalizeBody computes RawSHA256, DecodedSHA, encoding/kind, and JSONStyle on a WireBody.
func FinalizeBody(body *models.WireBody, contentType string) {
	wireclient.FinalizeBody(body, contentType)
}

// DecompressBody decodes gzip, br, zstd, deflate, or zlib HTTP payloads.
func DecompressBody(raw []byte, encoding string) ([]byte, error) {
	return wireclient.DecompressBody(raw, encoding)
}

// DetectBodyKind infers payload kind from Content-Type and byte inspection.
func DetectBodyKind(decoded []byte, contentType string) string {
	return wireclient.DetectBodyKind(decoded, contentType)
}

// SaveFixture redacts (unless KeepSecrets), saves raw body to *.body.bin, and writes *.fixture.json.
func SaveFixture(dir string, f *models.GoldenFixture, opts redact.Options) (string, string, error) {
	if f == nil {
		return "", "", fmt.Errorf("nil fixture")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	clean := redact.RedactFixture(f, opts)
	ct := HeaderValue(clean.Request.Headers, "content-type")
	FinalizeBody(&clean.Request.Body, ct)
	if clean.Response != nil {
		rct := HeaderValue(clean.Response.Headers, "content-type")
		FinalizeBody(&clean.Response.Body, rct)
	}

	slug := SafeSlug(clean.Name)
	if slug == "" {
		slug = SafeSlug(clean.ID)
	}
	if slug == "" {
		slug = "fixture"
	}
	var binPath string
	if len(clean.Request.Body.RawBytes) > 0 {
		binName := slug + ".body.bin"
		binPath = filepath.Join(dir, binName)
		if err := os.WriteFile(binPath, clean.Request.Body.RawBytes, 0o644); err != nil {
			return "", "", err
		}
		clean.Request.Body.BinFile = binName
	}
	if clean.Response != nil && len(clean.Response.Body.RawBytes) > 0 {
		respBinName := slug + ".resp.bin"
		if err := os.WriteFile(filepath.Join(dir, respBinName), clean.Response.Body.RawBytes, 0o644); err != nil {
			return "", "", err
		}
		clean.Response.Body.BinFile = respBinName
	}

	fixPath := filepath.Join(dir, slug+".fixture.json")
	data, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(fixPath, append(data, '\n'), 0o644); err != nil {
		return "", "", err
	}
	return fixPath, binPath, nil
}

// LoadFixture loads a *.fixture.json file and hydrates its binary body files from disk.
func LoadFixture(path string) (*models.GoldenFixture, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var fix models.GoldenFixture
	if err := json.Unmarshal(data, &fix); err != nil {
		return nil, fmt.Errorf("parsing fixture %s: %w", abs, err)
	}
	dir := filepath.Dir(abs)
	if fix.Request.Body.BinFile != "" {
		binBytes, err := os.ReadFile(filepath.Join(dir, fix.Request.Body.BinFile))
		if err != nil {
			return nil, fmt.Errorf("reading request body %s: %w", fix.Request.Body.BinFile, err)
		}
		fix.Request.Body.RawBytes = binBytes
	}
	if fix.Response != nil && fix.Response.Body.BinFile != "" {
		binBytes, err := os.ReadFile(filepath.Join(dir, fix.Response.Body.BinFile))
		if err != nil {
			return nil, fmt.Errorf("reading response body %s: %w", fix.Response.Body.BinFile, err)
		}
		fix.Response.Body.RawBytes = binBytes
	}
	return &fix, nil
}

// HeaderValue returns the first case-insensitive header value.
func HeaderValue(headers []models.HeaderKV, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.RawName, name) {
			return h.Value
		}
	}
	return ""
}

// SafeSlug normalizes fixture names into safe cross-platform file names.
func SafeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '/' || r == '.':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// SplitRawURL separates scheme, authority, rawPath, and rawQuery without altering percent-encoding or trailing `&`.
func SplitRawURL(rawURL string) (scheme, authority, rawPath, rawQuery string) {
	rest := rawURL
	if idx := strings.Index(rest, "://"); idx >= 0 {
		scheme = strings.ToLower(rest[:idx])
		rest = rest[idx+3:]
	} else {
		scheme = "https"
	}
	if hash := strings.IndexByte(rest, '#'); hash >= 0 {
		rest = rest[:hash]
	}
	qIdx := strings.IndexByte(rest, '?')
	if qIdx >= 0 {
		rawQuery = rest[qIdx+1:]
		rest = rest[:qIdx]
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		authority = rest[:slash]
		rawPath = rest[slash:]
	} else {
		authority = rest
		rawPath = "/"
	}
	return scheme, authority, rawPath, rawQuery
}
