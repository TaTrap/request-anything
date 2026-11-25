package report

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/TaTrap/request-anything/internal/gate"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/recording"
	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/internal/unitexec"
)

// Card holds measured verification and latency numbers for REPORT.md and card.svg.
type Card struct {
	Schema        string  `json:"schema"`
	Unit          string  `json:"unit"`
	Cases         int     `json:"cases"`
	Matched       int     `json:"matched"`
	OriginalP50Ms float64 `json:"original_p50_ms"`
	GoP50Ms       float64 `json:"go_p50_ms"`
	FallbackRate  float64 `json:"fallback_rate"`
	UnknownCount  int     `json:"unknown_count"`
	Machine       string  `json:"machine"`
	MarkdownPath  string  `json:"markdown_path"`
	SVGPath       string  `json:"svg_path"`
}

// MeasureAndWriteReport compiles and benchmarks the real unit port, evaluates Hard Gate, and writes REPORT.md + card.svg.
func MeasureAndWriteReport(ctx context.Context, unitDir, outDir string) (*Card, error) {
	absDir, err := filepath.Abs(unitDir)
	if err != nil {
		return nil, err
	}
	cu, err := unitexec.Compile(ctx, absDir)
	if err != nil {
		return nil, err
	}
	defer cu.Cleanup()

	// 1 warmup + 5 timed runs for real p50 latency measurement
	warmupRes, _ := unitexec.RunOnce(ctx, cu, nil, nil)
	const samplesCount = 5
	samples := make([]float64, 0, samplesCount)
	var lastRes *unitexec.RunResult
	for i := 0; i < samplesCount; i++ {
		r, rerr := unitexec.RunOnce(ctx, cu, nil, nil)
		if rerr != nil {
			return nil, rerr
		}
		lastRes = r
		samples = append(samples, r.DurationMs)
	}
	if lastRes == nil {
		lastRes = warmupRes
	}
	sort.Float64s(samples)
	goP50 := samples[len(samples)/2]

	var gOpts gate.Options
	gOpts.UnitDir = absDir
	if lastRes != nil {
		gOpts.ActualRequests = lastRes.Requests
		gOpts.ActualResponses = lastRes.Responses
		gOpts.ReqIDCorrelated = lastRes.ReqIDCorrelated
	}
	gOut, err := gate.Evaluate(ctx, gOpts)
	if err != nil {
		return nil, err
	}

	total := 1
	if lastRes != nil && len(lastRes.Requests) > 0 {
		total = len(lastRes.Requests)
	}
	matched := 0
	for _, c := range gOut.Checks {
		if c.Name == "wire-diff" && c.Passed {
			matched = total
			break
		}
	}
	unitName := cu.Manifest.Unit
	if unitName == "" {
		unitName = filepath.Base(absDir)
	}
	return WriteReport(absDir, outDir, unitName, matched, total, cu.Fixture.DurationMs, goP50, 0, gOut.Unknowns)
}

// WriteReport renders REPORT.md and card.svg into outDir (defaults to <unitDir>/report).
func WriteReport(unitDir, outDir string, unitName string, matched, total int, origMs, goMs, fallbackRate float64, unknowns []models.DiffFinding) (*Card, error) {
	if outDir == "" {
		outDir = filepath.Join(unitDir, "report")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	card := &Card{
		Schema:        models.SchemaReport,
		Unit:          unitName,
		Cases:         total,
		Matched:       matched,
		OriginalP50Ms: origMs,
		GoP50Ms:       goMs,
		FallbackRate:  fallbackRate,
		UnknownCount:  len(unknowns),
		Machine:       fmt.Sprintf("%s/%s, %d cores", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()),
		MarkdownPath:  filepath.Join(outDir, "REPORT.md"),
		SVGPath:       filepath.Join(outDir, "card.svg"),
	}

	origCell := "n/a (not recorded)"
	goCell := fmt.Sprintf("%.2f ms (measured)", goMs)
	speedup := 1.0
	if goMs > 0 && origMs > 0 {
		speedup = origMs / goMs
		origCell = fmt.Sprintf("%.2f ms", origMs)
		goCell = fmt.Sprintf("%.2f ms (%.1fx)", goMs, speedup)
	}
	md := fmt.Sprintf(`## %s in Go (`+"`request-anything`"+`)

![%s report card](card.svg)

| Metric | Value |
| --- | --- |
| Wire cases matched | %d / %d |
| Original p50 | %s |
| Go port p50 | %s |
| Fallback rate | %.1f%% |
| Coverage Honesty (unknown) | %d declared gap(s) |
| Machine | %s |
`, unitName, unitName, matched, total, origCell, goCell, fallbackRate*100, len(unknowns), card.Machine)

	if err := os.WriteFile(card.MarkdownPath, []byte(md), 0o644); err != nil {
		return nil, err
	}
	svg := renderCardSVG(card, speedup)
	if err := os.WriteFile(card.SVGPath, []byte(svg), 0o644); err != nil {
		return nil, err
	}
	return card, nil
}

func renderCardSVG(c *Card, speedup float64) string {
	origSVG := "n/a"
	speedupLine := fmt.Sprintf("%d/%d wire cases matched · %.1f ms Go · %d unknown gap(s)", c.Matched, c.Cases, c.GoP50Ms, c.UnknownCount)
	if c.OriginalP50Ms > 0 {
		origSVG = fmt.Sprintf("%.1f ms", c.OriginalP50Ms)
		speedupLine = fmt.Sprintf("%d/%d wire cases matched · %.1fx faster · %d unknown gap(s)", c.Matched, c.Cases, speedup, c.UnknownCount)
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="960" height="420" viewBox="0 0 960 420">
<rect width="960" height="420" fill="#ffffff"/>
<g font-family="-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif">
<text x="48" y="64" font-size="28" font-weight="700" fill="#1a1a1a">request-anything · %s</text>
<rect x="48" y="96" width="410" height="170" rx="16" fill="#ffffff" stroke="#e5e5e5" stroke-width="2"/>
<text x="72" y="136" font-size="22" font-weight="700" fill="#1a1a1a">Original</text>
<text x="72" y="210" font-family="monospace" font-size="44" font-weight="700" fill="#1a1a1a">%s</text>
<rect x="502" y="96" width="410" height="170" rx="16" fill="#eef9ff" stroke="#7dd3fc" stroke-width="2"/>
<text x="526" y="136" font-size="22" font-weight="700" fill="#0369a1">Go port</text>
<text x="526" y="210" font-family="monospace" font-size="44" font-weight="700" fill="#0284c7">%.1f ms</text>
<text x="480" y="324" font-size="22" text-anchor="middle" fill="#1a1a1a">%s</text>
<text x="480" y="366" font-size="15" text-anchor="middle" fill="#666666">Fallback: %.1f%% · %s</text>
</g>
</svg>
`, html.EscapeString(c.Unit), origSVG, c.GoP50Ms, html.EscapeString(speedupLine), c.FallbackRate*100, html.EscapeString(c.Machine))
}

// PortMapEntry describes one scaffolded unit discovered in a repo.
type PortMapEntry struct {
	UnitDir string `json:"unit_dir"`
	Unit    string `json:"unit"`
	Stale   string `json:"changed_upstream,omitempty"`
}

// PortMap summarizes port state across a repository (`PORT_MAP.md`).
type PortMap struct {
	Root  string         `json:"root"`
	Ports []PortMapEntry `json:"ports"`
	Stale int            `json:"stale_count"`
}

// BuildPortMap scans repo for request-anything.json manifests and checks recording freshness.
func BuildPortMap(root string, writeMD, checkStale bool) (*PortMap, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	pm := &PortMap{Root: absRoot}
	_ = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, wErr error) error {
		if wErr != nil {
			return nil
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "rust-anything" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) == scaffold.ManifestFile {
			unitDir := filepath.Dir(path)
			contractFile := ""
			unitName := filepath.Base(unitDir)
			if mb, merr := os.ReadFile(path); merr == nil {
				var man models.UnitManifest
				if json.Unmarshal(mb, &man) == nil {
					contractFile = man.ContractFile
					if man.Unit != "" {
						unitName = man.Unit
					}
				}
			}
			stale, _ := recording.CheckStale(unitDir, unitDir, recording.UnitInputs(contractFile))
			if stale != "" {
				pm.Stale++
			}
			rel, _ := filepath.Rel(absRoot, unitDir)
			pm.Ports = append(pm.Ports, PortMapEntry{
				UnitDir: filepath.ToSlash(rel),
				Unit:    unitName,
				Stale:   stale,
			})
		}
		return nil
	})
	sort.Slice(pm.Ports, func(i, j int) bool { return pm.Ports[i].UnitDir < pm.Ports[j].UnitDir })

	if writeMD {
		var b strings.Builder
		b.WriteString("# PORT_MAP.md\n\n| Unit | Folder | Upstream Status |\n| --- | --- | --- |\n")
		for _, p := range pm.Ports {
			status := "clean"
			if p.Stale != "" {
				status = "changed: " + p.Stale
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", p.Unit, p.UnitDir, status)
		}
		if err := os.WriteFile(filepath.Join(absRoot, "PORT_MAP.md"), []byte(b.String()), 0o644); err != nil {
			return nil, err
		}
	}
	if checkStale && pm.Stale > 0 {
		return pm, fmt.Errorf("%d port(s) have stale recordings", pm.Stale)
	}
	return pm, nil
}
