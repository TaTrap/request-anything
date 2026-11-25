package recording

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TaTrap/request-anything/internal/models"
)

const (
	RecordedFromFile = "recorded-from.json"
	KnownDiffsFile   = "known-diffs.jsonl"
	HistoryRelFile   = ".request-anything/diff-history.jsonl"
	StallAfter       = 3
)

// FingerprintMeta records the baseline FNV-1a digest of fixture & contract files.
type FingerprintMeta struct {
	Unit        string `json:"unit"`
	Files       int    `json:"files"`
	Fingerprint string `json:"fingerprint"`
}

// HistoryEntry records one diff run against a distinct port.go hash.
type HistoryEntry struct {
	Port   string `json:"port"`
	Passed int    `json:"passed"`
	Total  int    `json:"total"`
}

// ComputeFNV1a computes a stable 64-bit FNV-1a hex digest across sorted paths.
func ComputeFNV1a(baseDir string, relPaths []string) (string, int, error) {
	var files []string
	for _, rp := range relPaths {
		if rp == "" {
			continue
		}
		p := rp
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, rp)
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		_ = filepath.WalkDir(p, func(sub string, d fs.DirEntry, walkErr error) error {
			if walkErr == nil && !d.IsDir() {
				files = append(files, sub)
			}
			return nil
		})
	}
	sort.Strings(files)
	var h uint64 = 0xcbf29ce484222325
	eat := func(b []byte) {
		for _, c := range b {
			h ^= uint64(c)
			h *= 0x0100000001b3
		}
	}
	for _, f := range files {
		rel, err := filepath.Rel(baseDir, f)
		if err != nil {
			rel = f
		}
		eat([]byte(filepath.ToSlash(rel)))
		eat([]byte{0})
		data, err := os.ReadFile(f)
		if err != nil {
			return "", 0, err
		}
		eat(data)
		eat([]byte{0})
	}
	return fmt.Sprintf("%016x", h), len(files), nil
}

// UnitInputs returns the canonical input paths tracked in recorded-from.json for a scaffolded unit.
func UnitInputs(contractFile string) []string {
	if contractFile == "" {
		contractFile = "contract.yaml"
	}
	return []string{"fixtures", contractFile}
}

// SaveFingerprint writes recorded-from.json for staleness detection.
func SaveFingerprint(unitDir, unitName, baseDir string, inputs []string) error {
	hash, count, err := ComputeFNV1a(baseDir, inputs)
	if err != nil {
		return err
	}
	meta := FingerprintMeta{
		Unit:        unitName,
		Files:       count,
		Fingerprint: hash,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(unitDir, RecordedFromFile), append(data, '\n'), 0o644)
}

// CheckStale returns a non-empty reason string if recorded source inputs changed since record/scaffold.
func CheckStale(unitDir, baseDir string, inputs []string) (string, error) {
	metaBytes, err := os.ReadFile(filepath.Join(unitDir, RecordedFromFile))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var saved FingerprintMeta
	if err := json.Unmarshal(metaBytes, &saved); err != nil {
		return "", err
	}
	nowHash, _, err := ComputeFNV1a(baseDir, inputs)
	if err != nil {
		return "", err
	}
	if saved.Fingerprint != "" && saved.Fingerprint != nowHash {
		return fmt.Sprintf("%s changed since it was recorded: re-run scaffold/record before gating", saved.Unit), nil
	}
	return "", nil
}

// LoadKnownDiffs parses known-diffs.jsonl and rejects entries without a non-empty reason.
func LoadKnownDiffs(unitDir string) ([]models.KnownDiffEntry, error) {
	path := filepath.Join(unitDir, KnownDiffsFile)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []models.KnownDiffEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var e models.KnownDiffEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid JSON: %w", path, lineNo, err)
		}
		if e.Layer == "" || e.Path == "" {
			return nil, fmt.Errorf("%s:%d: entry requires `layer` and `path`", path, lineNo)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("%s:%d: entry requires a non-empty `reason`", path, lineNo)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

// ApplyKnownDiffs filters accepted divergences and returns any stale entries that no longer differ.
func ApplyKnownDiffs(res *models.DiffResult, entries []models.KnownDiffEntry) (accepted int, stale []models.KnownDiffEntry) {
	if len(entries) == 0 || res == nil {
		return 0, nil
	}
	used := make([]bool, len(entries))
	kept := make([]models.DiffFinding, 0, len(res.Findings))
	for _, f := range res.Findings {
		matchedIdx := -1
		for i, e := range entries {
			if (e.CaseID == "" || e.CaseID == res.CaseID) &&
				e.Layer == f.Layer &&
				e.Path == f.Path &&
				e.Expected == f.Expected &&
				e.Actual == f.Actual {
				matchedIdx = i
				break
			}
		}
		if matchedIdx >= 0 {
			used[matchedIdx] = true
			accepted++
		} else {
			kept = append(kept, f)
		}
	}
	res.Findings = kept
	res.Passed = len(res.Findings) == 0
	for i, e := range entries {
		if !used[i] {
			stale = append(stale, e)
		}
	}
	return accepted, stale
}

// TrackDiff records diff progress per distinct port.go content hash and detects stalling after STALL_AFTER edits.
func TrackDiff(unitDir string, passed, total int) (*models.Trend, error) {
	portBytes, err := os.ReadFile(filepath.Join(unitDir, "port.go"))
	if err != nil {
		return nil, err
	}
	var h uint64 = 0xcbf29ce484222325
	for _, b := range portBytes {
		h ^= uint64(b)
		h *= 0x0100000001b3
	}
	portHash := fmt.Sprintf("%016x", h)

	histPath := filepath.Join(unitDir, HistoryRelFile)
	var runs []HistoryEntry
	if raw, err := os.ReadFile(histPath); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e HistoryEntry
			if json.Unmarshal([]byte(line), &e) == nil && e.Total == total {
				runs = append(runs, e)
			}
		}
	}

	entry := HistoryEntry{Port: portHash, Passed: passed, Total: total}
	if n := len(runs); n > 0 && runs[n-1].Port == portHash {
		runs[n-1] = entry // Re-running diff on unchanged port.go does not advance stall counter
	} else {
		runs = append(runs, entry)
	}
	if len(runs) > 10 {
		runs = runs[len(runs)-10:]
	}
	if err := os.MkdirAll(filepath.Dir(histPath), 0o755); err != nil {
		return nil, err
	}
	var out strings.Builder
	for _, r := range runs {
		b, _ := json.Marshal(r)
		out.Write(b)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(histPath, []byte(out.String()), 0o644); err != nil {
		return nil, err
	}
	counts := make([]int, len(runs))
	for i, r := range runs {
		counts[i] = r.Passed
	}
	return ComputeTrend(counts, total), nil
}

// ComputeTrend mirrors rust-anything's exact stall rule: after 3 edits to port.go with no net gain while still failing.
func ComputeTrend(passed []int, total int) *models.Trend {
	n := len(passed)
	stalled := false
	if n > StallAfter && passed[n-1] < total {
		prevMax := 0
		for _, p := range passed[:n-StallAfter] {
			if p > prevMax {
				prevMax = p
			}
		}
		noGain := true
		for _, p := range passed[n-StallAfter:] {
			if p > prevMax {
				noGain = false
				break
			}
		}
		stalled = noGain
	}
	return &models.Trend{
		Passed:  passed,
		Total:   total,
		Stalled: stalled,
	}
}
