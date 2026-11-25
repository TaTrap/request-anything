package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/TaTrap/request-anything/internal/models"
)

// Finding reports a potential unredacted secret found in a file or directory.
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Kind    string `json:"kind"`
	Snippet string `json:"snippet"`
}

// Options configures fixture redaction behavior.
type Options struct {
	KeepSecrets bool
}

var (
	sensitiveKeys = []string{
		"password", "passwd", "pwd", "pass",
		"device_private_key", "signing_private_key", "private_key", "priv_key", "privkey",
		"secblob", "sec_key", "client_secret", "api_secret",
		"x-auth-token", "authorization", "sessionid", "sid_token", "session_guard",
	}

	pemPrivateRe   = regexp.MustCompile(`(?is)-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----`)
	secblobFileRe  = regexp.MustCompile(`(?i)\.secblob$`)
	kvSecretRe     = regexp.MustCompile(`(?i)["']?\b(password|passwd|device_private_key|private_key|client_secret|api_secret|secblob)\b["']?\s*[:=]\s*["']?([^\s"'&,;}{()]+)["']?`)
	bearerTokenRe  = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._\-]{12,}`)
	forbiddenExts  = map[string]bool{".sqlite": true, ".sqlite3": true, ".db": true, ".mitm": true, ".pcap": true, ".pcapng": true, ".secblob": true, ".pem": true, ".key": true, ".p12": true, ".pfx": true}
	safeMaskPrefix = "<REDACTED:"
)

// RedactValue replaces a sensitive value with a deterministic redacted token keeping length and hash prefix.
func RedactValue(val string) string {
	if val == "" || strings.HasPrefix(val, safeMaskPrefix) || strings.HasPrefix(val, "TEST_DUMMY_") {
		return val
	}
	sum := sha256.Sum256([]byte(val))
	return fmt.Sprintf("<REDACTED:len=%d:sha256=%s>", len(val), hex.EncodeToString(sum[:4]))
}

// IsSensitiveKey reports whether a query/header/JSON key holds credentials or private keys.
func IsSensitiveKey(key string) bool {
	low := strings.ToLower(strings.TrimSpace(key))
	for _, s := range sensitiveKeys {
		if low == s || strings.Contains(low, "private_key") || strings.Contains(low, "password") || strings.Contains(low, "secblob") {
			return true
		}
	}
	return false
}

// RedactFixture scrubs credentials, tokens, and private keys from a GoldenFixture copy before saving to git.
func RedactFixture(f *models.GoldenFixture, opts Options) *models.GoldenFixture {
	if f == nil || opts.KeepSecrets {
		return f
	}
	cp := *f
	cp.Request.Query = make([]models.QueryParam, len(f.Request.Query))
	queryChanged := false
	for i, q := range f.Request.Query {
		if IsSensitiveKey(q.RawKey) {
			redactedVal := RedactValue(q.RawValue)
			if redactedVal != q.RawValue {
				queryChanged = true
			}
			q.RawValue = redactedVal
		}
		cp.Request.Query[i] = q
	}
	if queryChanged {
		cp.Request.RawQuery = rebuildRawQuery(cp.Request.Query, cp.Request.TrailingAmp)
	} else if cp.Request.RawQuery != "" && strings.Contains(strings.ToLower(cp.Request.RawQuery), "password=") {
		cp.Request.RawQuery = ScrubText(cp.Request.RawQuery)
	}
	cp.Request.Headers = make([]models.HeaderKV, len(f.Request.Headers))
	for i, h := range f.Request.Headers {
		if IsSensitiveKey(h.RawName) {
			h.Value = RedactValue(h.Value)
		} else if strings.EqualFold(h.RawName, "cookie") {
			h.Value = RedactCookieValue(h.Value)
		}
		cp.Request.Headers[i] = h
	}
	if len(f.Request.Body.RawBytes) > 0 && utf8.Valid(f.Request.Body.RawBytes) {
		raw := string(f.Request.Body.RawBytes)
		scrubbed := ScrubText(raw)
		if scrubbed != raw {
			cp.Request.Body.RawBytes = []byte(scrubbed)
			sum := sha256.Sum256(cp.Request.Body.RawBytes)
			cp.Request.Body.RawSHA256 = hex.EncodeToString(sum[:])
			cp.Request.Body.DecodedSHA = cp.Request.Body.RawSHA256
		}
	}
	if f.Response != nil {
		respCopy := *f.Response
		respCopy.Headers = make([]models.HeaderKV, len(f.Response.Headers))
		for i, h := range f.Response.Headers {
			if IsSensitiveKey(h.RawName) {
				h.Value = RedactValue(h.Value)
			} else if strings.EqualFold(h.RawName, "set-cookie") || strings.EqualFold(h.RawName, "cookie") {
				h.Value = RedactCookieValue(h.Value)
			}
			respCopy.Headers[i] = h
		}
		if len(f.Response.Body.RawBytes) > 0 && utf8.Valid(f.Response.Body.RawBytes) {
			rawResp := string(f.Response.Body.RawBytes)
			scrubbedResp := ScrubText(rawResp)
			if scrubbedResp != rawResp {
				respCopy.Body.RawBytes = []byte(scrubbedResp)
				rSum := sha256.Sum256(respCopy.Body.RawBytes)
				respCopy.Body.RawSHA256 = hex.EncodeToString(rSum[:])
				respCopy.Body.DecodedSHA = respCopy.Body.RawSHA256
			}
		}
		cp.Response = &respCopy
	}
	return &cp
}

func rebuildRawQuery(params []models.QueryParam, trailingAmp bool) string {
	if len(params) == 0 && !trailingAmp {
		return ""
	}
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.RawKey)
		if p.HasEq {
			b.WriteByte('=')
			b.WriteString(p.RawValue)
		}
	}
	if trailingAmp {
		b.WriteByte('&')
	}
	return b.String()
}

// RedactCookieValue masks sensitive cookie items while keeping structural cookie names intact.
func RedactCookieValue(raw string) string {
	parts := strings.Split(raw, ";")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if k, v, ok := strings.Cut(trimmed, "="); ok && IsSensitiveKey(k) {
			lead := ""
			if strings.HasPrefix(part, " ") {
				lead = " "
			}
			parts[i] = lead + k + "=" + RedactValue(v)
		}
	}
	return strings.Join(parts, ";")
}

// ScrubText replaces PEM private key blocks, bearer tokens, and raw password/key assignments.
func ScrubText(text string) string {
	out := pemPrivateRe.ReplaceAllString(text, "<REDACTED:PEM_PRIVATE_KEY>")
	out = bearerTokenRe.ReplaceAllString(out, "Bearer <REDACTED:TOKEN>")
	out = kvSecretRe.ReplaceAllStringFunc(out, func(m string) string {
		sub := kvSecretRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		if strings.HasPrefix(sub[2], safeMaskPrefix) || strings.HasPrefix(sub[2], "TEST_DUMMY_") {
			return m
		}
		return strings.Replace(m, sub[2], RedactValue(sub[2]), 1)
	})
	return out
}

// AuditDirectory scans a fixture/unit directory for unredacted secrets or forbidden binary capture files.
func AuditDirectory(dir string) ([]Finding, error) {
	var findings []Finding
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "bin" || base == "dist" || base == "rust-anything" || base == "local-captures" || base == ".request-anything" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if forbiddenExts[ext] || secblobFileRe.MatchString(path) {
			findings = append(findings, Finding{
				File:    path,
				Kind:    "forbidden_artifact",
				Snippet: fmt.Sprintf("capture/secret file extension %q must not be committed in fixtures", ext),
			})
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, AuditBytes(path, data)...)
		return nil
	})
	return findings, err
}

// AuditRepository checks the entire source repository for forbidden capture/key artifacts
// and scans non-test files (excluding redact.go rule definitions) for unredacted secrets.
func AuditRepository(root string) ([]Finding, error) {
	var findings []Finding
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "bin" || base == "dist" || base == "rust-anything" || base == "local-captures" || base == ".request-anything" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if forbiddenExts[ext] || secblobFileRe.MatchString(path) {
			findings = append(findings, Finding{
				File:    path,
				Kind:    "forbidden_artifact",
				Snippet: fmt.Sprintf("capture/secret file extension %q must not be committed", ext),
			})
			return nil
		}
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") || base == "redact.go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, AuditBytes(path, data)...)
		return nil
	})
	return findings, err
}

// AuditBytes scans file contents for private keys, raw passwords, bearer tokens, or secblob secrets.
func AuditBytes(path string, data []byte) []Finding {
	var out []Finding
	text := string(data)
	if pemPrivateRe.MatchString(text) {
		out = append(out, Finding{
			File:    path,
			Kind:    "private_key",
			Snippet: "contains unredacted PEM private key header",
		})
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if m := kvSecretRe.FindStringSubmatch(line); len(m) >= 3 {
			val := strings.Trim(m[2], `"'`)
			if !strings.HasPrefix(val, safeMaskPrefix) && !strings.HasPrefix(val, "TEST_DUMMY_") && val != "null" && val != `""` {
				out = append(out, Finding{
					File:    path,
					Line:    i + 1,
					Kind:    "secret_literal",
					Snippet: fmt.Sprintf("unredacted %s assignment", m[1]),
				})
			}
		}
		if bearerTokenRe.MatchString(line) && !strings.Contains(line, safeMaskPrefix) && !strings.Contains(line, "TEST_DUMMY_") {
			out = append(out, Finding{
				File:    path,
				Line:    i + 1,
				Kind:    "bearer_token",
				Snippet: "contains unredacted bearer token",
			})
		}
	}
	return out
}
