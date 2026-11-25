package oracle

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/internal/process"
	"github.com/TaTrap/request-anything/pkg/models"
)

// VerifySignatureRule validates signed fields in either `byte_pinned` or `oracle_verify` mode.
func VerifySignatureRule(ctx context.Context, rule models.FieldRule, expectedVal, actualVal string, actualReq *models.WireRequest) *models.DiffFinding {
	mode := rule.SignerMode
	if mode == "" {
		mode = "oracle_verify"
	}
	if mode == "byte_pinned" {
		if expectedVal != actualVal {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "byte_pinned_signature_mismatch",
				Expected: expectedVal,
				Actual:   actualVal,
				Message:  fmt.Sprintf("byte_pinned signature mismatch on %s", rule.Target),
			}
		}
		return nil
	}

	// oracle_verify mode: validate structure & inner bindings rather than blind byte equality
	if actualVal == "" {
		return &models.DiffFinding{
			Layer:    "L4",
			Path:     rule.Target,
			Severity: "error",
			Kind:     "missing_signed_field",
			Message:  fmt.Sprintf("oracle_verify failed: %s is empty", rule.Target),
		}
	}
	if rule.Regex != "" {
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "invalid_rule_regex",
				Message:  err.Error(),
			}
		}
		if !re.MatchString(actualVal) {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "signature_format_mismatch",
				Expected: "match " + rule.Regex,
				Actual:   actualVal,
				Message:  fmt.Sprintf("signature %s does not match regex %s", rule.Target, rule.Regex),
			}
		}
	}

	switch rule.OracleHook {
	case "", "builtin:nonempty":
		return nil
	case "builtin:body-md5":
		var body []byte
		if actualReq != nil {
			body = actualReq.Body.RawBytes
		}
		sum := md5.Sum(body)
		want := strings.ToUpper(hex.EncodeToString(sum[:]))
		if !strings.EqualFold(actualVal, want) {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "body_md5_mismatch",
				Expected: want,
				Actual:   actualVal,
				Message:  fmt.Sprintf("body MD5 mismatch on %s: body MD5 is %s, header was %s", rule.Target, want, actualVal),
			}
		}
		return nil
	case "builtin:claims-json":
		dec, err := base64.StdEncoding.DecodeString(actualVal)
		if err != nil {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "claims_decode_error",
				Actual:   actualVal,
				Message:  fmt.Sprintf("cannot base64-decode signed claims payload: %v", err),
			}
		}
		var claims map[string]any
		if err := json.Unmarshal(dec, &claims); err != nil {
			return &models.DiffFinding{
				Layer:    "L4",
				Path:     rule.Target,
				Severity: "error",
				Kind:     "claims_parse_error",
				Message:  fmt.Sprintf("cannot decode signed claims JSON: %v", err),
			}
		}
		for k, want := range rule.Claims {
			got := fmt.Sprint(claims[k])
			if want == "@body_md5" && actualReq != nil {
				sum := md5.Sum(actualReq.Body.RawBytes)
				want = strings.ToUpper(hex.EncodeToString(sum[:]))
			} else if strings.HasPrefix(want, "@query.") && actualReq != nil {
				qName := strings.TrimPrefix(want, "@query.")
				want = extractQueryParam(actualReq.RawQuery, qName)
			}
			if want != "" && got != want {
				return &models.DiffFinding{
					Layer:    "L4",
					Path:     rule.Target + "." + k,
					Severity: "error",
					Kind:     "claims_binding_mismatch",
					Expected: want,
					Actual:   got,
					Message:  fmt.Sprintf("decoded signed claim %q=%q does not match expected binding %q", k, got, want),
				}
			}
		}
		return nil
	default:
		if strings.HasPrefix(rule.OracleHook, "cmd:") {
			return runExternalVerifier(ctx, strings.TrimPrefix(rule.OracleHook, "cmd:"), rule.Target, actualVal, actualReq)
		}
		return nil
	}
}

func runExternalVerifier(ctx context.Context, cmdStr, target, val string, req *models.WireRequest) *models.DiffFinding {
	payload, _ := json.Marshal(map[string]any{"target": target, "value": val, "request": req})
	prog := "sh"
	args := []string{"-c", cmdStr}
	if runtime.GOOS == "windows" {
		prog = "cmd.exe"
		args = []string{"/C", cmdStr}
	}
	out, err := process.Run(ctx, "", 10*time.Second, payload, nil, prog, args...)
	if err != nil {
		combined := ""
		if out != nil {
			combined = strings.TrimSpace(string(out.Stdout) + "\n" + string(out.Stderr))
		}
		return &models.DiffFinding{
			Layer:    "L4",
			Path:     target,
			Severity: "error",
			Kind:     "external_oracle_verify_failed",
			Actual:   combined,
			Message:  fmt.Sprintf("external oracle verifier failed: %v", err),
		}
	}
	return nil
}
