package unitexec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TaTrap/request-anything/internal/capture"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/process"
	"github.com/TaTrap/request-anything/internal/scaffold"
)

// CompiledUnit holds a pre-compiled test binary for a scaffolded Go unit.
type CompiledUnit struct {
	UnitDir  string
	BinPath  string
	Cleanup  func()
	Fixture  *models.GoldenFixture
	Manifest models.UnitManifest
}

// RunResult captures wire requests transmitted by port.go and responses served by LoopbackProxy.
type RunResult struct {
	Requests        []*models.WireRequest
	Responses       []*models.WireResponse
	ReqIDCorrelated bool
	DurationMs      float64
	Output          string
	Err             error
}

// Compile compiles unitDir into a standalone temporary Go test binary (`go test -c`) for fast repeated runs.
func Compile(ctx context.Context, unitDir string) (*CompiledUnit, error) {
	absDir, err := filepath.Abs(unitDir)
	if err != nil {
		return nil, err
	}
	manBytes, err := os.ReadFile(filepath.Join(absDir, scaffold.ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", scaffold.ManifestFile, err)
	}
	var man models.UnitManifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return nil, err
	}
	fix, err := ingest.LoadFixture(filepath.Join(absDir, filepath.FromSlash(man.FixtureFile)))
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "ra-unit-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	binName := "unit_capture.test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tmpDir, binName)
	out, err := process.Run(ctx, absDir, process.BuildTimeout, nil, nil, "go", "test", "-c", "-o", binPath, ".")
	if err != nil {
		detail := ""
		if out != nil {
			detail = strings.TrimSpace(string(out.Stdout) + "\n" + string(out.Stderr))
		}
		cleanup()
		return nil, fmt.Errorf("compiling unit %s: %w (%s)", absDir, err, detail)
	}
	return &CompiledUnit{
		UnitDir:  absDir,
		BinPath:  binPath,
		Cleanup:  cleanup,
		Fixture:  fix,
		Manifest: man,
	}, nil
}

// RunOnce executes the compiled unit binary once against a fresh LoopbackProxy with env-injected proxy settings.
func RunOnce(ctx context.Context, cu *CompiledUnit, extra map[string]string, extraOrder []string) (*RunResult, error) {
	if cu == nil {
		return nil, fmt.Errorf("nil CompiledUnit")
	}

	var respMu sync.Mutex
	var servedResponses []*models.WireResponse

	proxy, err := capture.StartLoopbackProxy(func(r *models.WireRequest) *models.WireResponse {
		var resp *models.WireResponse
		if cu.Fixture != nil && cu.Fixture.Response != nil {
			orig := cu.Fixture.Response
			hdrs := make([]models.HeaderKV, len(orig.Headers))
			copy(hdrs, orig.Headers)
			bodyCopy := orig.Body
			bodyCopy.RawBytes = append([]byte(nil), orig.Body.RawBytes...)
			resp = &models.WireResponse{
				Status:  orig.Status,
				Headers: hdrs,
				Body:    bodyCopy,
			}
		} else {
			resp = &models.WireResponse{
				Status:  200,
				Headers: []models.HeaderKV{{RawName: "content-type", Value: "application/json"}},
				Body:    models.WireBody{RawBytes: []byte(`{"status_code":0,"ok":true}`), Encoding: "raw"},
			}
		}
		respMu.Lock()
		servedResponses = append(servedResponses, resp)
		respMu.Unlock()
		return resp
	})
	if err != nil {
		return nil, err
	}
	defer proxy.Close()

	env := cleanUnitEnv()
	env = append(env,
		"REQUEST_ANYTHING_RUN_CAPTURE=1",
		"REQUEST_ANYTHING_DIFF_PROXY="+proxy.URL(),
		"REQUEST_ANYTHING_DID="+queryOrEnv(cu.Fixture, "REQUEST_ANYTHING_DID", "device_id", "did"),
		"REQUEST_ANYTHING_IID="+queryOrEnv(cu.Fixture, "REQUEST_ANYTHING_IID", "iid", "install_id"),
	)
	if len(extra) > 0 || len(extraOrder) > 0 {
		payload, _ := json.Marshal(map[string]any{
			"extra":       extra,
			"extra_order": extraOrder,
		})
		env = append(env, "REQUEST_ANYTHING_EXTRA_JSON="+string(payload))
	}

	start := time.Now()
	out, procErr := process.Run(ctx, cu.UnitDir, process.QuickTimeout, nil, env, cu.BinPath, "-test.run=^TestRequestAnythingWireCapture$")
	elapsedMs := float64(time.Since(start).Nanoseconds()) / 1e6

	combinedOut := ""
	exitCode := -1
	if out != nil {
		exitCode = out.ExitCode
		combinedOut = strings.TrimSpace(string(out.Stdout) + "\n" + string(out.Stderr))
	}

	respMu.Lock()
	respsCopy := append([]*models.WireResponse(nil), servedResponses...)
	respMu.Unlock()

	return &RunResult{
		Requests:        proxy.Captured(),
		Responses:       respsCopy,
		ReqIDCorrelated: procErr == nil && exitCode == 0,
		DurationMs:      elapsedMs,
		Output:          combinedOut,
		Err:             procErr,
	}, nil
}

// CaptureUnit compiles unitDir once, executes port.go via LoopbackProxy, and cleans up the temp binary.
func CaptureUnit(ctx context.Context, unitDir string) (*RunResult, *models.GoldenFixture, *models.UnitManifest, error) {
	cu, err := Compile(ctx, unitDir)
	if err != nil {
		return nil, nil, nil, err
	}
	defer cu.Cleanup()
	res, err := RunOnce(ctx, cu, nil, nil)
	if err != nil {
		return nil, cu.Fixture, &cu.Manifest, err
	}
	return res, cu.Fixture, &cu.Manifest, nil
}

func cleanUnitEnv() []string {
	skipPrefixes := []string{
		"REQUEST_ANYTHING_DIFF_PROXY=",
		"REQUEST_ANYTHING_MODE=",
		"REQUEST_ANYTHING_RUN_CAPTURE=",
		"REQUEST_ANYTHING_EXTRA_JSON=",
	}
	var env []string
	for _, entry := range os.Environ() {
		skip := false
		for _, pfx := range skipPrefixes {
			if strings.HasPrefix(strings.ToUpper(entry), pfx) {
				skip = true
				break
			}
		}
		if !skip {
			env = append(env, entry)
		}
	}
	return env
}

func queryOrEnv(fix *models.GoldenFixture, envKey string, qKeys ...string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	if fix != nil {
		for _, k := range qKeys {
			for _, qp := range fix.Request.Query {
				if qp.RawKey == k && qp.RawValue != "" && !strings.HasPrefix(qp.RawValue, "<REDACTED:") {
					return qp.RawValue
				}
			}
		}
	}
	return ""
}
