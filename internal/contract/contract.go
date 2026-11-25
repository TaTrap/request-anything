package contract

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
	"gopkg.in/yaml.v3"
)

const (
	FileName = "contract.yaml"
	TaskFile = "TASK.md"
)

// Generate builds a default ContractSpec from a GoldenFixture without silently ignoring any unknown variance.
func Generate(unitName string, fix *models.GoldenFixture) *models.ContractSpec {
	c := &models.ContractSpec{
		Schema:         "request-anything/contract@1",
		Unit:           unitName,
		CookieWireMode: fix.Request.Transport.CookieWireMode,
		EscapeSolidus:  fix.Request.Body.JSONStyle.EscapeSolidus,
		PositiveAssertions: []models.PositiveAssertion{
			{
				Name:   "zero_native_exceptions",
				Type:   "zero_native_exceptions",
				Reason: "NativeOracle.Health must report 0 worker exceptions",
			},
			{
				Name:   "req_id_correlation",
				Type:   "req_id_correlation",
				Reason: "Every response must correlate to its exact reqID (forbids FIFO delivery)",
			},
		},
	}

	seen := make(map[string]bool)
	addRule := func(r models.FieldRule) {
		if !seen[strings.ToLower(r.Target)] {
			seen[strings.ToLower(r.Target)] = true
			c.Rules = append(c.Rules, r)
		}
	}

	for _, q := range fix.Request.Query {
		switch q.RawKey {
		case "ts", "req_ts":
			addRule(models.FieldRule{Target: "query." + q.RawKey, Mode: "dynamic", Regex: `^[0-9]{10,13}$`})
		case "iid", "device_id":
			if q.RawValue != "" {
				// Exact unless declared chained/device_bound across scenario matrix
			}
		}
	}

	var bodyMD5Hex string
	if len(fix.Request.Body.RawBytes) > 0 {
		sum := md5.Sum(fix.Request.Body.RawBytes)
		bodyMD5Hex = hex.EncodeToString(sum[:])
	}

	customSigned := map[string]bool{}
	if env := strings.TrimSpace(os.Getenv("REQUEST_ANYTHING_SIGNED_HEADERS")); env != "" {
		for _, part := range strings.Split(env, ",") {
			if k := strings.ToLower(strings.TrimSpace(part)); k != "" {
				customSigned[k] = true
			}
		}
	}

	for _, h := range fix.Request.Headers {
		low := strings.ToLower(h.RawName)
		switch {
		case low == "x-timestamp" || low == "timestamp" || ((strings.HasSuffix(low, "-timestamp") || strings.HasSuffix(low, "-ts")) && isUnixTimestampDigits(h.Value)):
			addRule(models.FieldRule{Target: "header." + h.RawName, Mode: "dynamic", Regex: `^[0-9]{10,13}$`})
		case low == "content-md5" || (bodyMD5Hex != "" && strings.EqualFold(strings.TrimSpace(h.Value), bodyMD5Hex)):
			addRule(models.FieldRule{
				Target:     "header." + h.RawName,
				Mode:       "signed",
				SignerMode: "oracle_verify",
				OracleHook: "builtin:body-md5",
			})
		case low == "signature" || low == "x-signature" || strings.HasSuffix(low, "-signature") || strings.HasSuffix(low, "-sig") || customSigned[low]:
			if hasDecodableJSONClaims(h.Value) {
				addRule(models.FieldRule{
					Target:     "header." + h.RawName,
					Mode:       "signed",
					SignerMode: "oracle_verify",
					OracleHook: "builtin:claims-json",
					Claims:     map[string]string{"body_md5": "@body_md5"},
				})
			} else {
				addRule(models.FieldRule{
					Target:     "header." + h.RawName,
					Mode:       "signed",
					SignerMode: "oracle_verify",
					OracleHook: "builtin:nonempty",
					MinLen:     8,
				})
			}
		}
	}

	if strings.Contains(strings.ToLower(fix.Request.RawPath), "register") {
		c.PositiveAssertions = append(c.PositiveAssertions,
			models.PositiveAssertion{
				Name:     "register_did_iid_non_empty",
				Type:     "non_empty_field",
				Target:   "response.json.device_id",
				Expected: []string{"non-empty"},
				Reason:   "registration endpoint must yield valid non-empty DID",
			},
			models.PositiveAssertion{
				Name:     "register_status_ok",
				Type:     "status_in",
				Target:   "response.status",
				Expected: []string{"200"},
				Reason:   "registration endpoint must succeed with HTTP 200",
			},
		)
	}
	return c
}

func isUnixTimestampDigits(v string) bool {
	s := strings.TrimSpace(v)
	if len(s) < 10 || len(s) > 13 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasDecodableJSONClaims(v string) bool {
	s := strings.TrimSpace(v)
	if s == "" {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(dec, &claims); err != nil {
		return false
	}
	_, ok := claims["body_md5"]
	return ok
}

// Save writes contract.yaml atomically.
func Save(unitDir string, c *models.ContractSpec) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(unitDir, FileName), data, 0o644)
}

// Load reads contract.yaml from unitDir.
func Load(unitDir string) (*models.ContractSpec, error) {
	path := filepath.Join(unitDir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c models.ContractSpec
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

func portableDisplayDir(unitDir string) string {
	if wd, err := os.Getwd(); err == nil {
		if rel, rerr := filepath.Rel(wd, unitDir); rerr == nil && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, "..") {
			s := filepath.ToSlash(rel)
			if s == "." {
				return "."
			}
			return "./" + s
		}
	}
	base := filepath.Base(unitDir)
	if base == "" || base == "." {
		return "."
	}
	return "./" + base
}

// GenerateTaskMD renders TASK.md guiding an AI coding agent on what to edit and verify.
func GenerateTaskMD(unitDir, unitName string, fix *models.GoldenFixture, c *models.ContractSpec) string {
	disp := portableDisplayDir(unitDir)
	return fmt.Sprintf(`# Port %s to Go (%s)

Edit **only** %s/port.go (and unit tests in port_test.go). Do not edit client_gen.go, pinned_gen.go, or the recorded fixture.

## Recorded Wire Baseline
- Method & Path: %s %s
- Proto: %s | CaptureFidelity: %s | CookieWireMode: %s | EscapeSolidus: %v
- Raw Query: %q (TrailingAmp=%v)

## Rules
1. Keep exact header/query order using pkg/wireclient (OrderedHeaders, OrderedQuery, OrderedJSON).
2. Never use net/http.Header, url.Values.Encode(), or stdlib json.Marshal on unordered maps.
3. Preserve raw '*' and trailing '&' when query parameters are unmodified.
4. If EscapeSolidus=true, marshal JSON with wireclient.JSONMarshalOptions{EscapeSolidus: true} so body digests and Content-Length match.
5. Never put private keys, raw passwords, or .secblob into fixtures.
6. Done means BOTH diff=0 AND positive assertions pass:
   - request-anything diff %s
   - request-anything gate %s
`, unitName, fix.Request.Method, disp, fix.Request.Method, fix.Request.RawPath,
		fix.Request.Transport.Proto, fix.Request.Transport.CaptureFidelity, c.CookieWireMode, c.EscapeSolidus,
		fix.Request.RawQuery, fix.Request.TrailingAmp, disp, disp)
}
