package doctor

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"

	"github.com/TaTrap/request-anything/internal/capture"
	"github.com/TaTrap/request-anything/internal/mcp"
)

// Check reports status of one environment probe.
type Check struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // ok | missing | error
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
}

// Report aggregates all parallel probe checks.
type Report struct {
	OK     bool    `json:"ok"`
	Checks []Check `json:"checks"`
}

// Run executes all toolchain, CA, optional tool, and MCP stdio self-test probes in parallel.
func Run(ctx context.Context) *Report {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		checks []Check
	)
	add := func(c Check) {
		mu.Lock()
		checks = append(checks, c)
		mu.Unlock()
	}

	probes := []struct {
		name string
		bin  string
		args []string
		req  bool
		fix  string
	}{
		{"go", "go", []string{"version"}, true, "install Go 1.24+: scoop install go"},
		{"gofmt", "gofmt", []string{"-h"}, true, "ensure gofmt from Go SDK is on PATH"},
		{"mitmdump", "mitmdump", []string{"--version"}, false, "optional: pip install mitmproxy for .mitm files"},
		{"python3", "python3", []string{"--version"}, false, "optional: python3 for external mitm/oracle helpers"},
		{"tshark", "tshark", []string{"--version"}, false, "optional: install Wireshark/tshark for PCAP+SSLKEYLOG"},
		{"adb", "adb", []string{"version"}, false, "optional: install Android platform-tools"},
	}

	for _, p := range probes {
		wg.Add(1)
		go func(name, bin string, args []string, req bool, fix string) {
			defer wg.Done()
			out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
			if err != nil {
				add(Check{Name: name, Status: "missing", Required: req, Detail: err.Error(), Fix: fix})
				return
			}
			firstLine := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			add(Check{Name: name, Status: "ok", Required: req, Detail: firstLine})
		}(p.name, p.bin, p.args, p.req, p.fix)
	}

	// Local CA self-test
	wg.Add(1)
	go func() {
		defer wg.Done()
		ca, err := capture.NewLocalCA()
		if err != nil {
			add(Check{Name: "local_ca", Status: "error", Required: true, Detail: err.Error()})
			return
		}
		if _, err := ca.CertForHost("api.example.com"); err != nil {
			add(Check{Name: "local_ca", Status: "error", Required: true, Detail: err.Error()})
			return
		}
		add(Check{Name: "local_ca", Status: "ok", Required: true, Detail: "ECDSA P-256 CA + leaf cert signing OK"})
	}()

	// MCP stdio self-test
	wg.Add(1)
	go func() {
		defer wg.Done()
		in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
		var out strings.Builder
		if err := mcp.ServeIO(ctx, strings.NewReader(inputSafe(in)), &out); err != nil {
			add(Check{Name: "mcp_self_test", Status: "error", Required: true, Detail: err.Error()})
			return
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		var v map[string]any
		if len(lines) < 2 || json.Unmarshal([]byte(lines[1]), &v) != nil {
			add(Check{Name: "mcp_self_test", Status: "error", Required: true, Detail: "unexpected MCP self-test response"})
			return
		}
		add(Check{Name: "mcp_self_test", Status: "ok", Required: true, Detail: "stdio JSON-RPC 2.0 initialize + tools/list OK"})
	}()

	wg.Wait()
	allOK := true
	for _, c := range checks {
		if c.Required && c.Status != "ok" {
			allOK = false
			break
		}
	}
	return &Report{OK: allOK, Checks: checks}
}

func inputSafe(s string) string { return s }
