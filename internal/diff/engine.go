package diff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/oracle"
	"github.com/TaTrap/request-anything/internal/recording"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// Options configures a 6-layer surgical diff run.
type Options struct {
	Contract        *models.ContractSpec
	KnownDiffs      []models.KnownDiffEntry
	StrictTransport bool
	IncludeResponse bool
}

// CompareRequests runs the 6-Layer Surgical Wire Diff Engine and returns findings + explicit unknowns.
func CompareRequests(ctx context.Context, caseID string, expected *models.WireRequest, actual *models.WireRequest, expResp, actResp *models.WireResponse, opts Options) *models.DiffResult {
	res := &models.DiffResult{
		CaseID: caseID,
	}
	if expected == nil || actual == nil {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer:    "L1",
			Path:     "request",
			Severity: "error",
			Kind:     "nil_request",
			Message:  "expected or actual WireRequest is nil",
		})
		res.Summary = "nil request"
		return res
	}

	contract := opts.Contract
	if contract == nil {
		contract = &models.ContractSpec{}
	}

	// L4 Pre-check: Zero Silent Ignores on contract rules
	for _, r := range contract.Rules {
		if r.Mode == "ignore" && strings.TrimSpace(r.Reason) == "" {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer:    "L4",
				Path:     r.Target,
				Severity: "error",
				Kind:     "silent_ignore_forbidden",
				Message:  fmt.Sprintf("rule %q uses mode=ignore without a mandatory reason", r.Target),
			})
		}
	}

	// L1: URL & Raw Query
	diffL1URL(ctx, expected, actual, contract, res)

	// L2: Headers, H2 Pseudo-Headers & Cronet Cookie Crumbs
	diffL2Headers(ctx, expected, actual, contract, res)

	// L3: Body, Content-Encoding, EscapeSolidus, Raw Numbers & Schema-less Protobuf
	diffL3Body(ctx, expected, actual, contract, res)

	// L5: Transport Fingerprint (Opt-in Strict Mode + Coverage Honesty Unknowns)
	diffL5Transport(expected, actual, opts.StrictTransport || contract.StrictTransport, res)

	// L6: Response Parity (when live/recorded responses are compared)
	if opts.IncludeResponse && expResp != nil && actResp != nil {
		diffL6Response(expResp, actResp, contract, res)
	}

	// Apply known-diffs allowlist if provided
	if len(opts.KnownDiffs) > 0 {
		_, _ = recording.ApplyKnownDiffs(res, opts.KnownDiffs)
	}

	res.Passed = len(res.Findings) == 0
	if res.Passed {
		res.Summary = fmt.Sprintf("PASS (0 mismatches, %d unknown coverage note(s))", len(res.Unknowns))
	} else {
		res.Summary = fmt.Sprintf("FAIL (%d mismatch(es), %d unknown(s))", len(res.Findings), len(res.Unknowns))
	}
	return res
}

func findRule(c *models.ContractSpec, target string) *models.FieldRule {
	for i := range c.Rules {
		if strings.EqualFold(c.Rules[i].Target, target) {
			return &c.Rules[i]
		}
	}
	return nil
}

func validateFieldRule(ctx context.Context, rule *models.FieldRule, layer, path, expectedVal, actualVal string, actualReq *models.WireRequest, res *models.DiffResult) bool {
	if rule == nil {
		return false
	}
	switch rule.Mode {
	case "ignore":
		if strings.TrimSpace(rule.Reason) == "" {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer:    "L4",
				Path:     path,
				Severity: "error",
				Kind:     "silent_ignore_forbidden",
				Message:  "ignore rule missing reason",
			})
		}
		return true
	case "dynamic":
		if rule.MinLen > 0 && len(actualVal) < rule.MinLen {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer:    layer,
				Path:     path,
				Severity: "error",
				Kind:     "dynamic_min_len",
				Expected: fmt.Sprintf("len >= %d", rule.MinLen),
				Actual:   fmt.Sprintf("len=%d (%s)", len(actualVal), actualVal),
				Message:  fmt.Sprintf("%s shorter than min_len=%d", path, rule.MinLen),
			})
		}
		if rule.MaxLen > 0 && len(actualVal) > rule.MaxLen {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer:    layer,
				Path:     path,
				Severity: "error",
				Kind:     "dynamic_max_len",
				Expected: fmt.Sprintf("len <= %d", rule.MaxLen),
				Actual:   fmt.Sprintf("len=%d", len(actualVal)),
				Message:  fmt.Sprintf("%s longer than max_len=%d", path, rule.MaxLen),
			})
		}
		if rule.Regex != "" {
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L4", Path: path, Severity: "error", Kind: "invalid_regex", Message: err.Error(),
				})
			} else if !re.MatchString(actualVal) {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer:    layer,
					Path:     path,
					Severity: "error",
					Kind:     "dynamic_regex_mismatch",
					Expected: rule.Regex,
					Actual:   actualVal,
					Message:  fmt.Sprintf("%s value %q failed dynamic regex %s", path, actualVal, rule.Regex),
				})
			}
		}
		return true
	case "signed":
		if f := oracle.VerifySignatureRule(ctx, *rule, expectedVal, actualVal, actualReq); f != nil {
			res.Findings = append(res.Findings, *f)
		}
		return true
	case "chained":
		if expectedVal != "" && actualVal == "" {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer:    layer,
				Path:     path,
				Severity: "error",
				Kind:     "chained_empty_value",
				Expected: "non-empty chained value",
				Actual:   "",
				Message:  fmt.Sprintf("chained field %s is empty", path),
			})
		}
		return true
	default:
		return false
	}
}

func diffL1URL(ctx context.Context, exp, act *models.WireRequest, c *models.ContractSpec, res *models.DiffResult) {
	if exp.Method != act.Method {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L1", Path: "method", Severity: "error", Kind: "method_mismatch",
			Expected: exp.Method, Actual: act.Method, Message: "HTTP method mismatch",
		})
	}
	if exp.RawPath != act.RawPath {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L1", Path: "raw_path", Severity: "error", Kind: "path_mismatch",
			Expected: exp.RawPath, Actual: act.RawPath, Message: "raw path mismatch (check trailing slash or '//')",
		})
	}
	if exp.TrailingAmp != act.TrailingAmp {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L1", Path: "query.trailing_amp", Severity: "error", Kind: "trailing_amp_mismatch",
			Expected: fmt.Sprintf("%v", exp.TrailingAmp), Actual: fmt.Sprintf("%v", act.TrailingAmp),
			Message: "query trailing `&` mismatch",
		})
	}

	expQ := exp.Query
	if len(expQ) == 0 && exp.RawQuery != "" {
		expQ = wireclient.ParseRawQuery(exp.RawQuery).Params
	}
	actQ := act.Query
	if len(actQ) == 0 && act.RawQuery != "" {
		actQ = wireclient.ParseRawQuery(act.RawQuery).Params
	}

	maxLen := len(expQ)
	if len(actQ) > maxLen {
		maxLen = len(actQ)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(expQ) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L1", Path: fmt.Sprintf("query[%d].%s", i, actQ[i].RawKey), Severity: "error", Kind: "extra_query_param",
				Actual: actQ[i].RawKey + "=" + actQ[i].RawValue, Message: fmt.Sprintf("unexpected extra query param %q at index %d", actQ[i].RawKey, i),
			})
			continue
		}
		if i >= len(actQ) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L1", Path: fmt.Sprintf("query[%d].%s", i, expQ[i].RawKey), Severity: "error", Kind: "missing_query_param",
				Expected: expQ[i].RawKey + "=" + expQ[i].RawValue, Message: fmt.Sprintf("missing query param %q at index %d", expQ[i].RawKey, i),
			})
			continue
		}
		ep, ap := expQ[i], actQ[i]
		pPath := fmt.Sprintf("query[%d].%s", i, ep.RawKey)
		if ep.RawKey != ap.RawKey {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L1", Path: pPath, Severity: "error", Kind: "query_order_or_key_mismatch",
				Expected: ep.RawKey, Actual: ap.RawKey,
				Message: fmt.Sprintf("query param at index %d: expected key %q, got %q", i, ep.RawKey, ap.RawKey),
			})
			continue
		}
		if ep.HasEq != ap.HasEq {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L1", Path: pPath, Severity: "error", Kind: "query_has_eq_mismatch",
				Expected: fmt.Sprintf("HasEq=%v", ep.HasEq), Actual: fmt.Sprintf("HasEq=%v", ap.HasEq),
				Message: fmt.Sprintf("query param %q `=` presence mismatch", ep.RawKey),
			})
		}
		if rule := findRule(c, "query."+ep.RawKey); rule != nil {
			validateFieldRule(ctx, rule, "L1", "query."+ep.RawKey, ep.RawValue, ap.RawValue, act, res)
			continue
		}
		if ep.RawValue != ap.RawValue {
			if strings.HasPrefix(ep.RawValue, "<REDACTED:") {
				if unesc, err := url.PathUnescape(ap.RawValue); err == nil && unesc == ep.RawValue {
					continue
				}
			}
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L1", Path: pPath, Severity: "error", Kind: "query_value_mismatch",
				Expected: ep.RawValue, Actual: ap.RawValue,
				Message: fmt.Sprintf("query %q mismatch (check %%20 vs + or raw `*`)", ep.RawKey),
			})
		}
	}
}

func diffL2Headers(ctx context.Context, exp, act *models.WireRequest, c *models.ContractSpec, res *models.DiffResult) {
	if exp.Transport.CaptureFidelity == models.FidelityLossyHAR {
		res.Unknowns = append(res.Unknowns, models.DiffFinding{
			Layer:    "L2",
			Path:     "headers.pseudo_and_crumbs",
			Severity: "unknown",
			Kind:     "lossy_har_coverage_gap",
			Message:  "original source is lossy_har: HTTP/2 pseudo-header order and Cronet cookie crumbs cannot be proven from HAR",
		})
	} else {
		// Verify pseudo-header order when HTTP/2 is active
		if len(exp.Transport.PseudoOrder) > 0 && len(act.Transport.PseudoOrder) > 0 {
			if strings.Join(exp.Transport.PseudoOrder, ",") != strings.Join(act.Transport.PseudoOrder, ",") {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L2", Path: "headers.pseudo_order", Severity: "error", Kind: "h2_pseudo_order_mismatch",
					Expected: strings.Join(exp.Transport.PseudoOrder, " "),
					Actual:   strings.Join(act.Transport.PseudoOrder, " "),
					Message:  "HTTP/2 pseudo-header order mismatch",
				})
			}
		}
		// Verify CookieWireMode (h2_crumbs vs single_header)
		if exp.Transport.CookieWireMode == models.CookieH2Crumbs && act.Transport.CookieWireMode != models.CookieH2Crumbs {
			expCrumbs := countHeaderName(exp.Headers, "cookie")
			if expCrumbs > 1 {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L2", Path: "headers.cookie_wire_mode", Severity: "error", Kind: "cookie_crumbs_joined",
					Expected: string(models.CookieH2Crumbs), Actual: string(act.Transport.CookieWireMode),
					Message: "Cronet HTTP/2 requires separate cookie: crumb headers, but cookies were joined into single header",
				})
			}
		}
	}

	expRegs := regularHeaders(exp.Headers)
	actRegs := regularHeaders(act.Headers)
	expCrumbs := cookieCrumbs(expRegs)
	actCrumbs := cookieCrumbs(actRegs)
	if len(expCrumbs) > 0 || len(actCrumbs) > 0 {
		if rule := findRule(c, "header.cookie"); rule != nil {
			validateFieldRule(ctx, rule, "L2", "header.cookie", strings.Join(expCrumbs, "; "), strings.Join(actCrumbs, "; "), act, res)
		} else {
			if len(expCrumbs) != len(actCrumbs) {
				if exp.Transport.CaptureFidelity != models.FidelityLossyHAR {
					res.Findings = append(res.Findings, models.DiffFinding{
						Layer: "L2", Path: "header.cookie", Severity: "error", Kind: "cookie_count_mismatch",
						Expected: strings.Join(expCrumbs, "; "), Actual: strings.Join(actCrumbs, "; "),
						Message: "cookie crumb count/order mismatch",
					})
				}
			}
			minCrumbs := len(expCrumbs)
			if len(actCrumbs) < minCrumbs {
				minCrumbs = len(actCrumbs)
			}
			for i := 0; i < minCrumbs; i++ {
				ek, ev, eEq := strings.Cut(expCrumbs[i], "=")
				ak, av, aEq := strings.Cut(actCrumbs[i], "=")
				cPath := fmt.Sprintf("header.cookie[%d].%s", i, ek)
				if ek != ak || eEq != aEq {
					res.Findings = append(res.Findings, models.DiffFinding{
						Layer: "L2", Path: cPath, Severity: "error", Kind: "cookie_name_or_order_mismatch",
						Expected: expCrumbs[i], Actual: actCrumbs[i],
						Message: fmt.Sprintf("cookie crumb at index %d: expected %q, got %q", i, ek, ak),
					})
					continue
				}
				if cRule := findCookieRule(c, ek); cRule != nil {
					validateFieldRule(ctx, cRule, "L2", cPath, ev, av, act, res)
					continue
				}
				if ev != av {
					res.Findings = append(res.Findings, models.DiffFinding{
						Layer: "L2", Path: cPath, Severity: "error", Kind: "cookie_value_mismatch",
						Expected: ev, Actual: av,
						Message: fmt.Sprintf("cookie %q value mismatch", ek),
					})
				}
			}
		}
	}

	// Filter pseudo and transport-injected proxy headers unless explicitly present in expected
	expList := filterComparableHeaders(expRegs, actRegs, true)
	actList := filterComparableHeaders(actRegs, expRegs, false)

	maxLen := len(expList)
	if len(actList) > maxLen {
		maxLen = len(actList)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(expList) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L2", Path: fmt.Sprintf("headers[%d].%s", i, actList[i].RawName), Severity: "error", Kind: "extra_header",
				Actual: actList[i].RawName + ": " + actList[i].Value, Message: fmt.Sprintf("unexpected extra header %q", actList[i].RawName),
			})
			continue
		}
		if i >= len(actList) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L2", Path: fmt.Sprintf("headers[%d].%s", i, expList[i].RawName), Severity: "error", Kind: "missing_header",
				Expected: expList[i].RawName + ": " + expList[i].Value, Message: fmt.Sprintf("missing header %q", expList[i].RawName),
			})
			continue
		}
		eh, ah := expList[i], actList[i]
		hPath := fmt.Sprintf("headers[%d].%s", i, eh.RawName)
		if !strings.EqualFold(eh.RawName, ah.RawName) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L2", Path: hPath, Severity: "error", Kind: "header_order_mismatch",
				Expected: eh.RawName, Actual: ah.RawName,
				Message: fmt.Sprintf("header order mismatch at index %d: expected %q, got %q", i, eh.RawName, ah.RawName),
			})
			continue
		}
		if strings.EqualFold(exp.Transport.Proto, "HTTP/1.1") && eh.RawName != ah.RawName {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L2", Path: hPath, Severity: "error", Kind: "header_casing_mismatch",
				Expected: eh.RawName, Actual: ah.RawName,
				Message: fmt.Sprintf("HTTP/1.1 header casing mismatch: expected %q, got %q", eh.RawName, ah.RawName),
			})
		}
		if rule := findRule(c, "header."+eh.RawName); rule != nil {
			validateFieldRule(ctx, rule, "L2", "header."+eh.RawName, eh.Value, ah.Value, act, res)
			continue
		}
		if eh.Value != ah.Value {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L2", Path: hPath, Severity: "error", Kind: "header_value_mismatch",
				Expected: eh.Value, Actual: ah.Value,
				Message: fmt.Sprintf("header %q value mismatch", eh.RawName),
			})
		}
	}
}

func diffL3Body(ctx context.Context, exp, act *models.WireRequest, c *models.ContractSpec, res *models.DiffResult) {
	if exp.Body.Encoding != "" && act.Body.Encoding != "" && !strings.EqualFold(exp.Body.Encoding, act.Body.Encoding) {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L3", Path: "body.encoding", Severity: "error", Kind: "body_encoding_mismatch",
			Expected: exp.Body.Encoding, Actual: act.Body.Encoding, Message: "Content-Encoding mismatch",
		})
	}
	expRaw := exp.Body.RawBytes
	actRaw := act.Body.RawBytes
	if len(expRaw) == 0 && len(actRaw) == 0 {
		return
	}

	expDec, errE := ingest.DecompressBody(expRaw, exp.Body.Encoding)
	if errE != nil {
		expDec = expRaw
	}
	actDec, errA := ingest.DecompressBody(actRaw, act.Body.Encoding)
	if errA != nil {
		actDec = actRaw
	}

	kind := exp.Body.Kind
	if kind == "" {
		kind = ingest.DetectBodyKind(expDec, ingest.HeaderValue(exp.Headers, "content-type"))
	}

	switch kind {
	case "protobuf":
		findings := DiffProtoWire("body.proto", expDec, actDec)
		res.Findings = append(res.Findings, findings...)
		return
	case "json":
		if (exp.Body.JSONStyle.EscapeSolidus || c.EscapeSolidus) && bytes.Contains(expDec, []byte(`\/`)) && !bytes.Contains(actDec, []byte(`\/`)) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: "body.json.escape_solidus", Severity: "error", Kind: "json_escape_solidus_mismatch",
				Expected: `escaped solidus (\/) like Android JSONObject`,
				Actual:   `unescaped '/' (breaks body MD5 digest & Content-Length)`,
				Message:  "JSON body missing Android-style `\\/` solidus escaping (enable EscapeSolidus)",
			})
		}
		diffOrderedJSON(ctx, "body.json", expDec, actDec, c, act, res)
		return
	case "form":
		eq := wireclient.ParseRawQuery(string(expDec))
		aq := wireclient.ParseRawQuery(string(actDec))
		if len(eq.Params) != len(aq.Params) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: "body.form", Severity: "error", Kind: "form_param_count_mismatch",
				Expected: fmt.Sprintf("%d params", len(eq.Params)), Actual: fmt.Sprintf("%d params", len(aq.Params)),
				Message: "form param count mismatch",
			})
			return
		}
		for i := range eq.Params {
			if eq.Params[i].RawKey != aq.Params[i].RawKey {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L3", Path: fmt.Sprintf("body.form[%d]", i), Severity: "error", Kind: "form_key_mismatch",
					Expected: eq.Params[i].RawKey, Actual: aq.Params[i].RawKey, Message: "form key/order mismatch",
				})
				continue
			}
			if rule := findRule(c, "body.form."+eq.Params[i].RawKey); rule != nil {
				validateFieldRule(ctx, rule, "L3", "body.form."+eq.Params[i].RawKey, eq.Params[i].RawValue, aq.Params[i].RawValue, act, res)
				continue
			}
			if eq.Params[i].RawValue != aq.Params[i].RawValue {
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L3", Path: "body.form." + eq.Params[i].RawKey, Severity: "error", Kind: "form_value_mismatch",
					Expected: eq.Params[i].RawValue, Actual: aq.Params[i].RawValue, Message: "form value mismatch",
				})
			}
		}
		return
	default:
		if rule := findRule(c, "body.raw"); rule != nil {
			validateFieldRule(ctx, rule, "L3", "body.raw", hex.EncodeToString(expRaw), hex.EncodeToString(actRaw), act, res)
			return
		}
		if !bytes.Equal(expRaw, actRaw) {
			es := sha256.Sum256(expRaw)
			as := sha256.Sum256(actRaw)
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: "body.raw", Severity: "error", Kind: "raw_body_bytes_mismatch",
				Expected: fmt.Sprintf("len=%d sha256=%s", len(expRaw), hex.EncodeToString(es[:8])),
				Actual:   fmt.Sprintf("len=%d sha256=%s", len(actRaw), hex.EncodeToString(as[:8])),
				Message:  "raw binary body bytes mismatch",
			})
		}
	}
}

func diffOrderedJSON(ctx context.Context, prefix string, expRaw, actRaw []byte, c *models.ContractSpec, actReq *models.WireRequest, res *models.DiffResult) {
	ev, err1 := wireclient.UnmarshalOrdered(expRaw)
	av, err2 := wireclient.UnmarshalOrdered(actRaw)
	if err1 != nil || err2 != nil {
		if !bytes.Equal(expRaw, actRaw) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: prefix, Severity: "error", Kind: "json_parse_or_raw_mismatch",
				Expected: string(expRaw), Actual: string(actRaw),
				Message: fmt.Sprintf("JSON parse/raw mismatch (expErr=%v actErr=%v)", err1, err2),
			})
		}
		return
	}
	compareJSONValues(ctx, prefix, ev, av, c, actReq, res)
}

func compareJSONValues(ctx context.Context, path string, ev, av any, c *models.ContractSpec, actReq *models.WireRequest, res *models.DiffResult) {
	if rule := findRule(c, path); rule != nil {
		validateFieldRule(ctx, rule, "L3", path, fmt.Sprint(ev), fmt.Sprint(av), actReq, res)
		return
	}

	switch ex := ev.(type) {
	case *wireclient.OrderedMap:
		ax, ok := av.(*wireclient.OrderedMap)
		if !ok {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_type_mismatch",
				Expected: "object", Actual: fmt.Sprintf("%T", av), Message: "JSON type mismatch",
			})
			return
		}
		if !c.IgnoreKeyOrder {
			if len(ex.Pairs) == len(ax.Pairs) {
				for i := range ex.Pairs {
					if ex.Pairs[i].Key != ax.Pairs[i].Key {
						res.Findings = append(res.Findings, models.DiffFinding{
							Layer: "L3", Path: fmt.Sprintf("%s.__key_order[%d]", path, i), Severity: "error", Kind: "json_key_order_mismatch",
							Expected: ex.Pairs[i].Key, Actual: ax.Pairs[i].Key, Message: "JSON object key order mismatch",
						})
						break
					}
				}
			}
		}
		for _, ep := range ex.Pairs {
			subPath := path + "." + ep.Key
			aval, exists := ax.Get(ep.Key)
			if !exists {
				if rule := findRule(c, subPath); rule != nil && rule.Mode == "ignore" {
					continue
				}
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L3", Path: subPath, Severity: "error", Kind: "json_missing_key",
					Expected: fmt.Sprint(ep.Value), Message: fmt.Sprintf("missing JSON key %q (null vs omitted is distinct)", ep.Key),
				})
				continue
			}
			compareJSONValues(ctx, subPath, ep.Value, aval, c, actReq, res)
		}
		for _, ap := range ax.Pairs {
			subPath := path + "." + ap.Key
			if _, exists := ex.Get(ap.Key); !exists {
				if rule := findRule(c, subPath); rule != nil && rule.Mode == "ignore" {
					continue
				}
				res.Findings = append(res.Findings, models.DiffFinding{
					Layer: "L3", Path: subPath, Severity: "error", Kind: "json_extra_key",
					Actual: fmt.Sprint(ap.Value), Message: fmt.Sprintf("unexpected extra JSON key %q", ap.Key),
				})
			}
		}
	case []any:
		ax, ok := av.([]any)
		if !ok {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_type_mismatch",
				Expected: "array", Actual: fmt.Sprintf("%T", av), Message: "JSON type mismatch",
			})
			return
		}
		if len(ex) != len(ax) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_array_len_mismatch",
				Expected: fmt.Sprintf("len=%d", len(ex)), Actual: fmt.Sprintf("len=%d", len(ax)), Message: "JSON array length mismatch",
			})
			return
		}
		for i := range ex {
			compareJSONValues(ctx, fmt.Sprintf("%s[%d]", path, i), ex[i], ax[i], c, actReq, res)
		}
	case json.Number:
		ax, ok := av.(json.Number)
		if !ok {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_type_mismatch",
				Expected: fmt.Sprintf("number(%s)", ex.String()), Actual: fmt.Sprintf("%T(%v)", av, av),
				Message: fmt.Sprintf("JSON type mismatch at %s (int vs string is strict)", path),
			})
			return
		}
		if !NumbersClose(ex, ax, c.FloatTolerance) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_number_mismatch",
				Expected: ex.String(), Actual: ax.String(),
				Message: fmt.Sprintf("JSON number mismatch at %s (`3` != `3.0`)", path),
			})
		}
	default:
		if fmt.Sprintf("%T:%v", ev, ev) != fmt.Sprintf("%T:%v", av, av) {
			res.Findings = append(res.Findings, models.DiffFinding{
				Layer: "L3", Path: path, Severity: "error", Kind: "json_value_mismatch",
				Expected: fmt.Sprintf("%T(%v)", ev, ev), Actual: fmt.Sprintf("%T(%v)", av, av),
				Message: fmt.Sprintf("JSON value/type mismatch at %s", path),
			})
		}
	}
}

func diffL5Transport(exp, act *models.WireRequest, strict bool, res *models.DiffResult) {
	// Coverage Honesty: explicitly mark unobserved HTTP/2 & HTTP/3 wire internals as unknown.
	res.Unknowns = append(res.Unknowns,
		models.DiffFinding{
			Layer: "L5", Path: "transport.hpack_dynamic_table_and_huffman", Severity: "unknown",
			Kind:    "unobservable_transport_layer",
			Message: "HPACK dynamic table compression, Huffman coding, CONTINUATION frames, and frame timing are not preserved across capture/replay",
		},
		models.DiffFinding{
			Layer: "L5", Path: "transport.qpack_quic", Severity: "unknown",
			Kind:    "unobservable_transport_layer",
			Message: "HTTP/3 QPACK & QUIC transport parameters require separate v0.3 H3 adapter",
		},
	)

	if exp.Transport.CaptureFidelity != models.FidelityLosslessWire {
		res.Unknowns = append(res.Unknowns, models.DiffFinding{
			Layer: "L5", Path: "transport.tls_and_h2_settings", Severity: "unknown",
			Kind:    "capture_fidelity_insufficient",
			Message: fmt.Sprintf("capture_fidelity=%s lacks TLS ClientHello JA3/JA4 and raw H2 SETTINGS", exp.Transport.CaptureFidelity),
		})
		return
	}

	if !strict {
		return
	}

	if exp.Transport.Proto != "" && act.Transport.Proto != "" && exp.Transport.Proto != act.Transport.Proto {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L5", Path: "transport.proto", Severity: "error", Kind: "proto_mismatch",
			Expected: exp.Transport.Proto, Actual: act.Transport.Proto, Message: "HTTP protocol version mismatch",
		})
	}
	if exp.Transport.JA4 != "" && act.Transport.JA4 != "" && exp.Transport.JA4 != act.Transport.JA4 {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L5", Path: "transport.ja4", Severity: "error", Kind: "ja4_mismatch",
			Expected: exp.Transport.JA4, Actual: act.Transport.JA4, Message: "TLS ClientHello JA4 fingerprint mismatch",
		})
	}
	if len(exp.Transport.H2Settings) > 0 && fmt.Sprint(exp.Transport.H2Settings) != fmt.Sprint(act.Transport.H2Settings) {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L5", Path: "transport.h2_settings", Severity: "error", Kind: "h2_settings_mismatch",
			Expected: fmt.Sprint(exp.Transport.H2Settings), Actual: fmt.Sprint(act.Transport.H2Settings),
			Message: "HTTP/2 SETTINGS frame ID/order mismatch",
		})
	}
}

func findCookieRule(c *models.ContractSpec, name string) *models.FieldRule {
	if r := findRule(c, "cookie."+name); r != nil {
		return r
	}
	return findRule(c, "header.cookie."+name)
}

func diffL6Response(exp, act *models.WireResponse, c *models.ContractSpec, res *models.DiffResult) {
	if exp.Status != act.Status {
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L6", Path: "response.status", Severity: "error", Kind: "response_status_mismatch",
			Expected: fmt.Sprintf("%d", exp.Status), Actual: fmt.Sprintf("%d", act.Status),
			Message: "HTTP response status mismatch",
		})
	}
	expDec := wireclient.DecodedResponseBytes(exp)
	actDec := wireclient.DecodedResponseBytes(act)
	if len(expDec) == 0 && len(actDec) == 0 {
		return
	}
	expLines := strings.Split(strings.TrimSuffix(string(expDec), "\n"), "\n")
	actLines := strings.Split(strings.TrimSuffix(string(actDec), "\n"), "\n")
	if !LinesMatchInAnyOrder(expLines, actLines, c.FloatTolerance) {
		// Try ordered JSON structural check if both are JSON
		if json.Valid(expDec) && json.Valid(actDec) {
			diffOrderedJSON(context.Background(), "response.body.json", expDec, actDec, c, nil, res)
			return
		}
		res.Findings = append(res.Findings, models.DiffFinding{
			Layer: "L6", Path: "response.body", Severity: "error", Kind: "response_body_mismatch",
			Expected: string(expDec), Actual: string(actDec),
			Message: "response body mismatch",
		})
	}
}

func regularHeaders(all []models.HeaderKV) []models.HeaderKV {
	var out []models.HeaderKV
	for _, h := range all {
		if !h.IsPseudo && !strings.HasPrefix(h.RawName, ":") {
			out = append(out, h)
		}
	}
	return out
}

func countHeaderName(all []models.HeaderKV, name string) int {
	n := 0
	for _, h := range all {
		if strings.EqualFold(h.RawName, name) {
			n++
		}
	}
	return n
}

func cookieCrumbs(all []models.HeaderKV) []string {
	var out []string
	for _, h := range all {
		if strings.EqualFold(h.RawName, "cookie") {
			out = append(out, wireclient.SplitCookieCrumbs(h.Value)...)
		}
	}
	return out
}

func filterComparableHeaders(list, other []models.HeaderKV, isExpected bool) []models.HeaderKV {
	hasName := func(items []models.HeaderKV, name string) bool {
		for _, h := range items {
			if strings.EqualFold(h.RawName, name) {
				return true
			}
		}
		return false
	}
	var out []models.HeaderKV
	for _, h := range list {
		low := strings.ToLower(h.RawName)
		// Proxy/transport auto headers (Host, Content-Length, Accept-Encoding, User-Agent fallback)
		// are ignored ONLY if not present on the expected fixture side.
		if low == "cookie" {
			continue // compared specifically by cookie crumb validator above
		}
		if !isExpected && (low == "content-length" || low == "accept-encoding" || low == "connection" || low == "host") && !hasName(other, low) {
			continue
		}
		out = append(out, h)
	}
	return out
}
