package fuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/unitexec"
)

// Options configures deterministic request edge-case fuzzing.
type Options struct {
	UnitDir string
	Cases   int
	Seed    uint64
	Budget  time.Duration
	Keep    string // "" | "mismatches" | "all"
}

// Outcome summarizes live compiled fuzz execution.
type Outcome struct {
	Seed       uint64              `json:"seed"`
	Rounds     int                 `json:"rounds"`
	Cases      int                 `json:"cases"`
	Mismatches int                 `json:"mismatches"`
	Failures   []string            `json:"failures,omitempty"`
	Traps      []models.QueryParam `json:"generated_traps,omitempty"`
	Kept       int                 `json:"kept"`
	Restore    string              `json:"restore_guard"`
}

var StringTraps = []string{
	"hello world",
	"1216*2623",
	"İstanbul",
	"ılık ırmak",
	"👨\u200D👩\u200D👧 family",
	"https://api.example.com/a/b",
	"",
	"a+b=c&d",
}

// GenerateQueryTraps creates deterministic edge-case query variations from seed.
func GenerateQueryTraps(seed uint64, count int) []models.QueryParam {
	if count <= 0 {
		count = len(StringTraps)
	}
	state := seed
	next := func() uint64 {
		state += 0x9E3779B97F4A7C15
		z := (state ^ (state >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	out := make([]models.QueryParam, 0, count)
	for i := 0; i < count; i++ {
		val := StringTraps[int(next()%uint64(len(StringTraps)))]
		out = append(out, models.QueryParam{
			RawKey:   fmt.Sprintf("trap_%d", i),
			RawValue: val,
			HasEq:    i%5 != 0,
			Modified: true,
		})
	}
	return out
}

// WithFileRestore runs fn and restores targetFile to its original contents if anything fails (RAII restore).
func WithFileRestore(targetFile string, fn func() error) error {
	orig, readErr := os.ReadFile(targetFile)
	existed := readErr == nil
	err := fn()
	if err != nil {
		if existed {
			_ = os.WriteFile(targetFile, orig, 0o644)
		} else {
			_ = os.Remove(targetFile)
		}
	}
	return err
}

// Run compiles the unit's port.go, injects deterministic trap inputs over LoopbackProxy, and verifies wire round-trips.
func Run(ctx context.Context, opts Options) (*Outcome, error) {
	if opts.Seed == 0 {
		opts.Seed = uint64(time.Now().UnixNano())
	}
	if opts.Cases <= 0 {
		opts.Cases = 5
	}
	if opts.UnitDir == "" {
		return nil, fmt.Errorf("fuzz requires UnitDir")
	}
	absDir, err := filepath.Abs(opts.UnitDir)
	if err != nil {
		return nil, err
	}

	cu, err := unitexec.Compile(ctx, absDir)
	if err != nil {
		return nil, err
	}
	defer cu.Cleanup()

	baseSpec, err := contract.Load(absDir)
	if err != nil {
		baseSpec = contract.Generate(cu.Manifest.EndpointName, cu.Fixture)
	}

	var candidateKeys []string
	for _, qp := range cu.Fixture.Request.Query {
		if qp.RawKey != "" && !strings.EqualFold(qp.RawKey, "aid") {
			candidateKeys = append(candidateKeys, qp.RawKey)
		}
	}
	if len(candidateKeys) == 0 && len(cu.Fixture.Request.Query) > 0 {
		candidateKeys = []string{cu.Fixture.Request.Query[0].RawKey}
	}

	traps := GenerateQueryTraps(opts.Seed, opts.Cases)
	var deadline time.Time
	if opts.Budget > 0 {
		deadline = time.Now().Add(opts.Budget)
	}

	var executedCases int
	var mismatches int
	var failures []string
	var savedLines []string

	for i, trap := range traps {
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}
		executedCases++
		targetKey := trap.RawKey
		if len(candidateKeys) > 0 {
			targetKey = candidateKeys[i%len(candidateKeys)]
		}
		traps[i].RawKey = targetKey

		extra := map[string]string{targetKey: trap.RawValue}
		res, rerr := unitexec.RunOnce(ctx, cu, extra, []string{targetKey})
		if rerr != nil || res == nil || len(res.Requests) == 0 {
			mismatches++
			msg := fmt.Sprintf("case[%d] %s=%q: no wire capture (%v %s)", i, targetKey, trap.RawValue, rerr, resOutput(res))
			failures = append(failures, msg)
			savedLines = append(savedLines, toJSONLine(i, targetKey, trap.RawValue, false, msg))
			continue
		}

		act := res.Requests[0]
		foundVal, ok := findQueryDecoded(act.Query, targetKey)
		var dRes *models.DiffResult
		if len(candidateKeys) > 0 {
			fuzzSpec := cloneContractWithDynamicQuery(baseSpec, targetKey)
			dRes = diff.CompareRequests(ctx, fmt.Sprintf("fuzz-%d", i), &cu.Fixture.Request, act, nil, nil, diff.Options{
				Contract: fuzzSpec,
			})
		}

		caseOK := ok && foundVal == trap.RawValue && (dRes == nil || dRes.Passed)
		if !caseOK {
			mismatches++
			why := fmt.Sprintf("round-trip decoded=%q (present=%v)", foundVal, ok)
			if dRes != nil && !dRes.Passed {
				why += "; diff: " + dRes.Summary
			}
			failures = append(failures, fmt.Sprintf("case[%d] %s=%q: %s", i, targetKey, trap.RawValue, why))
			if opts.Keep == "mismatches" || opts.Keep == "all" {
				savedLines = append(savedLines, toJSONLine(i, targetKey, trap.RawValue, false, why))
			}
		} else if opts.Keep == "all" {
			savedLines = append(savedLines, toJSONLine(i, targetKey, trap.RawValue, true, "ok"))
		}
	}

	restorePath := filepath.Join(absDir, "fuzz-cases.jsonl")
	kept := 0
	if len(savedLines) > 0 && (opts.Keep == "all" || opts.Keep == "mismatches") {
		_ = WithFileRestore(restorePath, func() error {
			return os.WriteFile(restorePath, []byte(strings.Join(savedLines, "\n")+"\n"), 0o644)
		})
		kept = len(savedLines)
	}

	return &Outcome{
		Seed:       opts.Seed,
		Rounds:     1,
		Cases:      executedCases,
		Mismatches: mismatches,
		Failures:   failures,
		Traps:      traps[:executedCases],
		Kept:       kept,
		Restore:    restorePath,
	}, nil
}

func cloneContractWithDynamicQuery(src *models.ContractSpec, targetKey string) *models.ContractSpec {
	cp := *src
	cp.Rules = append([]models.FieldRule(nil), src.Rules...)
	target := "query." + targetKey
	replaced := false
	for i := range cp.Rules {
		if strings.EqualFold(cp.Rules[i].Target, target) {
			cp.Rules[i] = models.FieldRule{Target: target, Mode: "dynamic"}
			replaced = true
		}
	}
	if !replaced {
		cp.Rules = append(cp.Rules, models.FieldRule{Target: target, Mode: "dynamic"})
	}
	return &cp
}

func findQueryDecoded(params []models.QueryParam, key string) (string, bool) {
	for _, p := range params {
		if p.RawKey == key {
			if decoded, err := wireQueryUnescape(p.RawValue); err == nil {
				return decoded, true
			}
			return p.RawValue, true
		}
	}
	return "", false
}

func wireQueryUnescape(raw string) (string, error) {
	// Percent-unescape without converting literal `+` unless percent-encoded (`%2B`).
	return url.PathUnescape(raw)
}

func resOutput(res *unitexec.RunResult) string {
	if res == nil {
		return ""
	}
	return res.Output
}

func toJSONLine(idx int, key, val string, ok bool, msg string) string {
	b, _ := json.Marshal(map[string]any{
		"case": idx, "key": key, "value": val, "ok": ok, "detail": msg,
	})
	return string(b)
}
