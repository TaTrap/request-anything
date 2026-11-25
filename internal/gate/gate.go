package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/oracle"
	"github.com/TaTrap/request-anything/internal/process"
	"github.com/TaTrap/request-anything/internal/recording"
	"github.com/TaTrap/request-anything/internal/redact"
	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/internal/unitexec"
	"github.com/TaTrap/request-anything/pkg/wireclient"
)

// Options configures a Hard Gate evaluation run.
type Options struct {
	UnitDir         string
	ActualRequests  []*models.WireRequest
	ActualResponses []*models.WireResponse
	OracleHealth    *oracle.OracleHealth
	VisitedPaths    []string
	ReqIDCorrelated bool
	SkipGoChecks    bool // Allows pure library/in-memory gate evaluations when unitDir isn't a standalone Go module
	StrictTransport bool
	IncludeResponse bool
}

var stubPattern = regexp.MustCompile(`(?i)panic\(\s*"(?:todo|not implemented)|//\s*TODO\b`)

// Evaluate runs all Hard Gate checks (gofmt, vet, test, no-stubs, secret-hygiene, freshness, contract, 6-layer diff, known-diffs, positive-assertions, coverage-honesty).
func Evaluate(ctx context.Context, opts Options) (*models.GateOutcome, error) {
	absDir, err := filepath.Abs(opts.UnitDir)
	if err != nil {
		return nil, err
	}
	var checks []models.Check

	if !opts.SkipGoChecks {
		checks = append(checks, runGoChecks(ctx, absDir)...)
	}

	checks = append(checks, checkNoStubs(absDir))
	checks = append(checks, checkSecretHygiene(absDir))

	// Load manifest, fixture, contract
	manBytes, err := os.ReadFile(filepath.Join(absDir, scaffold.ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", scaffold.ManifestFile, err)
	}
	var manifest models.UnitManifest
	if err := json.Unmarshal(manBytes, &manifest); err != nil {
		return nil, err
	}

	fixPath := filepath.Join(absDir, filepath.FromSlash(manifest.FixtureFile))
	fix, err := ingest.LoadFixture(fixPath)
	if err != nil {
		return nil, err
	}
	spec, err := contract.Load(absDir)
	if err != nil {
		checks = append(checks, models.Check{
			Name:   "contract-completeness",
			Passed: false,
			Detail: err.Error(),
			Fix:    fmt.Sprintf("restore or regenerate %s", filepath.Join(absDir, contract.FileName)),
		})
		return finalizeOutcome(checks, nil, nil), nil
	}

	checks = append(checks, checkContractCompleteness(spec))

	if staleWhy, serr := recording.CheckStale(absDir, absDir, recording.UnitInputs(manifest.ContractFile)); serr != nil {
		checks = append(checks, models.Check{Name: "recording-freshness", Passed: false, Detail: serr.Error()})
	} else if staleWhy != "" {
		checks = append(checks, models.Check{
			Name:   "recording-freshness",
			Passed: false,
			Detail: staleWhy,
			Fix:    fmt.Sprintf("request-anything refresh %s", absDir),
		})
	} else {
		checks = append(checks, models.Check{Name: "recording-freshness", Passed: true, Detail: "fixture and contract match recorded-from.json"})
	}

	known, kErr := recording.LoadKnownDiffs(absDir)
	if kErr != nil {
		checks = append(checks, models.Check{
			Name:   "known-diffs",
			Passed: false,
			Detail: kErr.Error(),
			Fix:    fmt.Sprintf("add non-empty `reason` to every entry in %s", filepath.Join(absDir, recording.KnownDiffsFile)),
		})
	}

	// Execute live port.go via LoopbackProxy automatically when caller did not pre-supply ActualRequests.
	var execCaptureErr string
	if len(opts.ActualRequests) == 0 {
		runRes, _, _, capErr := unitexec.CaptureUnit(ctx, absDir)
		if capErr != nil {
			execCaptureErr = capErr.Error()
		} else if runRes != nil {
			opts.ActualRequests = runRes.Requests
			opts.ActualResponses = runRes.Responses
			opts.ReqIDCorrelated = runRes.ReqIDCorrelated
			if runRes.Err != nil && len(opts.ActualRequests) == 0 {
				execCaptureErr = fmt.Sprintf("%v (%s)", runRes.Err, runRes.Output)
			}
		}
	}

	// Wire diff across provided/captured actual requests
	var allUnknowns []models.DiffFinding
	var trend *models.Trend
	if len(opts.ActualRequests) == 0 {
		detail := "no actual wire requests captured from Go port"
		if execCaptureErr != "" {
			detail = execCaptureErr
		}
		checks = append(checks, models.Check{
			Name:   "wire-diff",
			Passed: false,
			Detail: detail,
			Fix:    fmt.Sprintf("request-anything diff %s", absDir),
		})
	} else {
		passedCount := 0
		var diffDetails []string
		var staleAll []models.KnownDiffEntry
		for i, actReq := range opts.ActualRequests {
			var actResp *models.WireResponse
			if i < len(opts.ActualResponses) {
				actResp = opts.ActualResponses[i]
			}
			res := diff.CompareRequests(ctx, fix.ID, &fix.Request, actReq, fix.Response, actResp, diff.Options{
				Contract:        spec,
				StrictTransport: opts.StrictTransport || manifest.StrictTransport,
				IncludeResponse: opts.IncludeResponse,
			})
			_, stale := recording.ApplyKnownDiffs(res, known)
			staleAll = append(staleAll, stale...)
			allUnknowns = append(allUnknowns, res.Unknowns...)
			if res.Passed {
				passedCount++
			} else {
				for _, f := range res.Findings {
					diffDetails = append(diffDetails, fmt.Sprintf("[%s] %s: %s", f.Layer, f.Path, f.Message))
				}
			}
		}
		trend, _ = recording.TrackDiff(absDir, passedCount, len(opts.ActualRequests))
		if kErr == nil {
			if len(staleAll) > 0 {
				checks = append(checks, models.Check{
					Name:   "known-diffs",
					Passed: false,
					Detail: fmt.Sprintf("%d known-diff entry(s) no longer differ (stale_known)", len(staleAll)),
					Fix:    fmt.Sprintf("remove resolved entries from %s", filepath.Join(absDir, recording.KnownDiffsFile)),
				})
			} else {
				checks = append(checks, models.Check{Name: "known-diffs", Passed: true, Detail: fmt.Sprintf("%d accepted divergence(s), 0 stale", len(known))})
			}
		}
		if len(diffDetails) > 0 {
			checks = append(checks, models.Check{
				Name:   "wire-diff",
				Passed: false,
				Detail: strings.Join(diffDetails, "; "),
				Fix:    fmt.Sprintf("fix %s and re-run `request-anything diff %s`", filepath.Join(absDir, "port.go"), absDir),
			})
		} else {
			checks = append(checks, models.Check{
				Name:   "wire-diff",
				Passed: true,
				Detail: fmt.Sprintf("%d/%d wire case(s) matched", passedCount, len(opts.ActualRequests)),
			})
		}
	}

	// Positive Assertions (prevents dual-fail error_code=7 false greens)
	checks = append(checks, evaluatePositiveAssertions(spec, opts))

	// Coverage Honesty check (reports explicit unknowns transparently)
	checks = append(checks, models.Check{
		Name:   "coverage-honesty",
		Passed: true,
		Detail: fmt.Sprintf("%d unverified/unknown coverage item(s) declared honestly", len(allUnknowns)),
	})

	return finalizeOutcome(checks, allUnknowns, trend), nil
}

func runGoChecks(ctx context.Context, unitDir string) []models.Check {
	var checks []models.Check
	if out, err := process.Run(ctx, unitDir, process.QuickTimeout, nil, nil, "gofmt", "-l", "."); err != nil || strings.TrimSpace(string(out.Stdout)) != "" {
		detail := strings.TrimSpace(string(out.Stdout))
		if err != nil {
			detail = err.Error()
		}
		checks = append(checks, models.Check{
			Name: "gofmt", Passed: false, Detail: detail, Fix: fmt.Sprintf("gofmt -w %s", unitDir),
		})
	} else {
		checks = append(checks, models.Check{Name: "gofmt", Passed: true, Detail: "formatted"})
	}

	if out, err := process.Run(ctx, unitDir, process.BuildTimeout, nil, nil, "go", "vet", "."); err != nil {
		checks = append(checks, models.Check{
			Name: "go vet", Passed: false, Detail: strings.TrimSpace(string(out.Stderr)), Fix: "fix go vet diagnostics",
		})
	} else {
		checks = append(checks, models.Check{Name: "go vet", Passed: true, Detail: "no warnings"})
	}

	if out, err := process.Run(ctx, unitDir, process.BuildTimeout, nil, nil, "go", "test", "."); err != nil {
		checks = append(checks, models.Check{
			Name: "go test", Passed: false, Detail: strings.TrimSpace(string(out.Stdout) + string(out.Stderr)), Fix: "fix failing unit tests in port_test.go",
		})
	} else {
		checks = append(checks, models.Check{Name: "go test", Passed: true, Detail: "passed"})
	}
	return checks
}

func checkNoStubs(unitDir string) models.Check {
	portPath := filepath.Join(unitDir, "port.go")
	data, err := os.ReadFile(portPath)
	if err != nil {
		return models.Check{Name: "no-stubs", Passed: false, Detail: err.Error(), Fix: "restore port.go"}
	}
	if stubPattern.Match(data) {
		return models.Check{
			Name:   "no-stubs",
			Passed: false,
			Detail: "port.go still contains todo/not-implemented panic or TODO marker",
			Fix:    fmt.Sprintf("finish implementing %s", portPath),
		}
	}
	return models.Check{Name: "no-stubs", Passed: true, Detail: "no stubs remaining in port.go"}
}

func checkSecretHygiene(unitDir string) models.Check {
	findings, err := redact.AuditDirectory(unitDir)
	if err != nil {
		return models.Check{Name: "secret-hygiene", Passed: false, Detail: err.Error()}
	}
	if len(findings) > 0 {
		var msgs []string
		for _, f := range findings {
			msgs = append(msgs, fmt.Sprintf("%s:%d (%s: %s)", f.File, f.Line, f.Kind, f.Snippet))
		}
		return models.Check{
			Name:   "secret-hygiene",
			Passed: false,
			Detail: strings.Join(msgs, "; "),
			Fix:    "redact private keys, raw passwords, and .secblob before committing fixtures",
		}
	}
	return models.Check{Name: "secret-hygiene", Passed: true, Detail: "no unredacted secrets or forbidden artifacts"}
}

func checkContractCompleteness(c *models.ContractSpec) models.Check {
	for _, r := range c.Rules {
		if r.Mode == "ignore" && strings.TrimSpace(r.Reason) == "" {
			return models.Check{
				Name:   "contract-completeness",
				Passed: false,
				Detail: fmt.Sprintf("silent ignore forbidden on %q: missing reason", r.Target),
				Fix:    "add an explicit `reason` or remove the ignore rule in contract.yaml",
			}
		}
	}
	return models.Check{Name: "contract-completeness", Passed: true, Detail: fmt.Sprintf("%d rule(s), 0 silent ignores", len(c.Rules))}
}

func evaluatePositiveAssertions(c *models.ContractSpec, opts Options) models.Check {
	var failures []string
	for _, a := range c.PositiveAssertions {
		switch a.Type {
		case "zero_native_exceptions":
			if opts.OracleHealth != nil && (!opts.OracleHealth.Healthy || opts.OracleHealth.WorkerExceptions > 0) {
				failures = append(failures, fmt.Sprintf("%s: native worker exceptions=%d (%s)", a.Name, opts.OracleHealth.WorkerExceptions, opts.OracleHealth.LastError))
			}
		case "req_id_correlation":
			if len(opts.ActualResponses) > 0 && !opts.ReqIDCorrelated {
				failures = append(failures, fmt.Sprintf("%s: response correlation did not verify per-request reqID", a.Name))
			}
		case "required_endpoints":
			visited := make(map[string]bool)
			for _, ep := range opts.VisitedPaths {
				visited[ep] = true
			}
			for _, reqEp := range a.Expected {
				if !visited[reqEp] {
					failures = append(failures, fmt.Sprintf("%s: required endpoint %q was never reached", a.Name, reqEp))
				}
			}
		case "status_in":
			if len(opts.ActualResponses) == 0 {
				failures = append(failures, fmt.Sprintf("%s: no response recorded for status_in check", a.Name))
				continue
			}
			last := opts.ActualResponses[len(opts.ActualResponses)-1]
			ok := false
			for _, expStr := range a.Expected {
				if expCode, err := strconv.Atoi(expStr); err == nil && last.Status == expCode {
					ok = true
					break
				}
			}
			if !ok {
				failures = append(failures, fmt.Sprintf("%s: status %d not in %v", a.Name, last.Status, a.Expected))
			}
		case "non_empty_field", "json_path_eq", "json_path_ne":
			val := extractTargetValue(a.Target, opts)
			switch a.Type {
			case "non_empty_field":
				if strings.TrimSpace(val) == "" || val == "<nil>" {
					failures = append(failures, fmt.Sprintf("%s: field %s is empty", a.Name, a.Target))
				}
			case "json_path_eq":
				if len(a.Expected) > 0 && val != a.Expected[0] {
					failures = append(failures, fmt.Sprintf("%s: %s=%q != %q", a.Name, a.Target, val, a.Expected[0]))
				}
			case "json_path_ne":
				if len(a.Expected) > 0 && val == a.Expected[0] {
					failures = append(failures, fmt.Sprintf("%s: %s=%q must not equal %q", a.Name, a.Target, val, a.Expected[0]))
				}
			}
		}
	}
	if len(failures) > 0 {
		return models.Check{
			Name:   "positive-assertions",
			Passed: false,
			Detail: strings.Join(failures, "; "),
			Fix:    "resolve runtime/business failure (check DID/IID, native exceptions, or endpoint chain)",
		}
	}
	return models.Check{
		Name:   "positive-assertions",
		Passed: true,
		Detail: fmt.Sprintf("%d positive assertion(s) passed", len(c.PositiveAssertions)),
	}
}

func extractTargetValue(target string, opts Options) string {
	if strings.HasPrefix(target, "response.json.") && len(opts.ActualResponses) > 0 {
		last := opts.ActualResponses[len(opts.ActualResponses)-1]
		decoded := wireclient.DecodedResponseBytes(last)
		val, err := wireclient.UnmarshalOrdered(decoded)
		if err != nil {
			return ""
		}
		pathParts := strings.Split(strings.TrimPrefix(target, "response.json."), ".")
		cur := val
		for _, p := range pathParts {
			om, ok := cur.(*wireclient.OrderedMap)
			if !ok {
				return ""
			}
			next, exists := om.Get(p)
			if !exists {
				return ""
			}
			cur = next
		}
		if cur == nil {
			return ""
		}
		return fmt.Sprint(cur)
	}
	return ""
}

func finalizeOutcome(checks []models.Check, unknowns []models.DiffFinding, trend *models.Trend) *models.GateOutcome {
	allPassed := true
	for _, c := range checks {
		if !c.Passed {
			allPassed = false
			break
		}
	}
	return &models.GateOutcome{
		Passed:   allPassed,
		Checks:   checks,
		Unknowns: unknowns,
		Trend:    trend,
	}
}
