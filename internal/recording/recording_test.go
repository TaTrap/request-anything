package recording

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TaTrap/request-anything/internal/models"
)

func TestStallDetectorAndKnownDiffs(t *testing.T) {
	dir := t.TempDir()
	// Rerunning diff on unchanged port.go ("a") counts once; then 3 non-improving edits trigger stalled=true.
	attempts := []struct {
		code   string
		passed int
	}{
		{"a", 1},
		{"a", 2},
		{"b", 2},
		{"c", 2},
		{"d", 2},
	}
	var trend *models.Trend
	var err error
	for _, a := range attempts {
		if err := os.WriteFile(filepath.Join(dir, "port.go"), []byte(a.code), 0o644); err != nil {
			t.Fatal(err)
		}
		trend, err = TrackDiff(dir, a.passed, 5)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !trend.Stalled {
		t.Fatalf("expected Stalled=true, got %+v", trend)
	}

	// Known diffs missing reason must be rejected
	if err := os.WriteFile(filepath.Join(dir, KnownDiffsFile), []byte(`{"layer":"L1","path":"q","expected":"a","actual":"b","reason":""}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKnownDiffs(dir); err == nil {
		t.Fatalf("expected error for known-diff without reason")
	}
}
