package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TaTrap/request-anything/internal/analyze"
	"github.com/TaTrap/request-anything/internal/auto"
	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/internal/flow"
	"github.com/TaTrap/request-anything/internal/fuzz"
	"github.com/TaTrap/request-anything/internal/gate"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/redact"
	"github.com/TaTrap/request-anything/internal/report"
	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/internal/shadow"
	"github.com/TaTrap/request-anything/internal/unitexec"
)

const ProtocolVersion = "2025-06-18"

var Version = "0.1.0"

// ToolMeta defines MCP tool annotations.
type ToolMeta struct {
	Name        string
	Title       string
	ReadOnly    bool
	Destructive bool
	Idempotent  bool
	OpenWorld   bool
	MVPv01      bool
}

var toolMetas = []ToolMeta{
	{Name: "import", Title: "Import request capture", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: false, MVPv01: true},
	{Name: "scaffold", Title: "Scaffold Go request unit", ReadOnly: false, Destructive: false, Idempotent: false, OpenWorld: false, MVPv01: true},
	{Name: "diff", Title: "Run 6-layer wire diff", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: true, MVPv01: true},
	{Name: "gate", Title: "Check definition of done", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: true, MVPv01: true},
	{Name: "flow_replay", Title: "Replay stateful flow DAG", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: true, MVPv01: true},
	{Name: "analyze", Title: "Analyze fixtures & waves", ReadOnly: true, Destructive: false, Idempotent: true, OpenWorld: false},
	{Name: "refresh", Title: "Regenerate client_gen.go", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: false},
	{Name: "fuzz", Title: "Fuzz request edge traps", ReadOnly: false, Destructive: false, Idempotent: false, OpenWorld: true},
	{Name: "shadow", Title: "Generate shadow wrapper", ReadOnly: false, Destructive: false, Idempotent: false, OpenWorld: false},
	{Name: "report", Title: "Write REPORT.md & card.svg", ReadOnly: false, Destructive: false, Idempotent: true, OpenWorld: true},
	{Name: "map", Title: "Map repository ports", ReadOnly: true, Destructive: false, Idempotent: true, OpenWorld: false},
	{Name: "go", Title: "Autonomous agent loop", ReadOnly: false, Destructive: false, Idempotent: false, OpenWorld: true},
}

// Serve runs the MCP stdio server over os.Stdin and os.Stdout.
func Serve(ctx context.Context) error {
	return ServeIO(ctx, os.Stdin, os.Stdout)
}

// ServeIO runs newline-delimited JSON-RPC 2.0 over arbitrary streams with 1 exclusive writer goroutine.
func ServeIO(ctx context.Context, in io.Reader, out io.Writer) error {
	writeCh := make(chan []byte, 64)
	writerDone := make(chan error, 1)

	// 1 exclusive writer goroutine owns stdout
	go func() {
		bw := bufio.NewWriter(out)
		var writeErr error
		for msg := range writeCh {
			if _, err := bw.Write(msg); err != nil {
				writeErr = err
				break
			}
			if err := bw.WriteByte('\n'); err != nil {
				writeErr = err
				break
			}
			if err := bw.Flush(); err != nil {
				writeErr = err
				break
			}
		}
		writerDone <- writeErr
	}()

	emit := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		writeCh <- b
	}

	var runMu sync.Mutex
	running := make(map[string]context.CancelFunc)
	var wg sync.WaitGroup

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req map[string]any
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			emit(rpcError(nil, -32700, fmt.Sprintf("parse error: %v", err)))
			continue
		}
		method, _ := req["method"].(string)
		idVal, hasID := req["id"]

		if method == "notifications/cancelled" {
			if params, ok := req["params"].(map[string]any); ok {
				key := canonicalID(params["requestId"])
				runMu.Lock()
				if cancelFn, exists := running[key]; exists {
					cancelFn()
					delete(running, key)
				}
				runMu.Unlock()
			}
			continue
		}

		if method == "tools/call" && hasID {
			key := canonicalID(idVal)
			callCtx, cancelFn := context.WithCancel(ctx)
			runMu.Lock()
			running[key] = cancelFn
			runMu.Unlock()

			wg.Add(1)
			go func(r map[string]any, idKey string, cctx context.Context, cfn context.CancelFunc) {
				defer wg.Done()
				defer cfn()
				defer func() {
					if rec := recover(); rec != nil {
						runMu.Lock()
						_, stillActive := running[idKey]
						delete(running, idKey)
						runMu.Unlock()
						if stillActive && cctx.Err() == nil {
							emit(rpcError(r["id"], -32603, fmt.Sprintf("tool panicked: %v", rec)))
						}
					}
				}()

				params, _ := r["params"].(map[string]any)
				toolName, _ := params["name"].(string)
				progTok := extractProgressToken(params)
				if progTok != nil {
					emit(progressNotification(progTok, 0, "running "+toolName))
				}

				resp := HandleMessage(cctx, r)

				runMu.Lock()
				_, stillActive := running[idKey]
				delete(running, idKey)
				runMu.Unlock()

				if !stillActive || cctx.Err() != nil {
					return // Cancelled: suppress progress & final response
				}
				if progTok != nil {
					emit(progressNotification(progTok, 1, toolName+" finished"))
				}
				if resp != nil {
					emit(resp)
				}
			}(req, key, callCtx, cancelFn)
			continue
		}

		if resp := HandleMessage(ctx, req); resp != nil {
			emit(resp)
		}
	}

	wg.Wait()
	close(writeCh)
	err := <-writerDone
	if scanErr := sc.Err(); scanErr != nil {
		return scanErr
	}
	return err
}

// HandleMessage processes a single JSON-RPC 2.0 request and returns nil for notifications.
func HandleMessage(ctx context.Context, req map[string]any) map[string]any {
	idVal, hasID := req["id"]
	if !hasID || idVal == nil {
		return nil
	}
	method, _ := req["method"].(string)

	switch method {
	case "initialize":
		protoVer := ProtocolVersion
		if params, ok := req["params"].(map[string]any); ok {
			if pv, ok := params["protocolVersion"].(string); ok && pv != "" {
				protoVer = pv
			}
		}
		return rpcResult(idVal, map[string]any{
			"protocolVersion": protoVer,
			"capabilities": map[string]any{
				"tools":   map[string]any{},
				"prompts": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "request-anything",
				"version": Version,
			},
			"instructions": "Wire-level request porting to Go. Loop: import -> scaffold -> edit port.go -> diff -> gate. Never declare done before gate passes.",
		})
	case "ping":
		return rpcResult(idVal, map[string]any{})
	case "tools/list":
		return rpcResult(idVal, map[string]any{"tools": ToolsList()})
	case "prompts/list":
		return rpcResult(idVal, ListPrompts())
	case "prompts/get":
		params, _ := req["params"].(map[string]any)
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		p, err := GetPrompt(name, args)
		if err != nil {
			return rpcError(idVal, -32602, err.Error())
		}
		return rpcResult(idVal, p)
	case "tools/call":
		params, _ := req["params"].(map[string]any)
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		val, err := CallTool(ctx, name, args)
		if err != nil {
			msg := err.Error()
			return rpcResult(idVal, map[string]any{
				"content":           []map[string]any{{"type": "text", "text": msg}},
				"structuredContent": ClassifyFailure(msg, args),
				"isError":           true,
			})
		}
		pretty, _ := json.MarshalIndent(val, "", "  ")
		return rpcResult(idVal, map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(pretty)}},
			"structuredContent": val,
			"isError":           false,
		})
	default:
		return rpcError(idVal, -32601, fmt.Sprintf("unknown method `%s`", method))
	}
}

// ToolsList returns tool schemas with MCP annotations.
func ToolsList() []map[string]any {
	unitArg := map[string]any{"type": "string", "description": "Path to scaffolded Go unit directory."}
	schemas := map[string]map[string]any{
		"import": {
			"description": "Import cURL, HAR, gzipped capture SQLite, Frida JSON, raw HTTP, .mitm, or PCAP+SSLKEYLOG into redacted Golden Wire Fixtures.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"source":       map[string]any{"type": "string", "description": "Input file path or inline curl command."},
					"format":       map[string]any{"type": "string", "enum": []string{"auto", "curl", "har", "sqlite", "frida", "raw", "mitm", "pcap"}},
					"keylog":       map[string]any{"type": "string", "description": "Optional SSLKEYLOGFILE path when importing .pcap/.pcapng."},
					"out":          map[string]any{"type": "string", "description": "Output fixture folder."},
					"keep_secrets": map[string]any{"type": "boolean", "description": "Keep raw secrets (local-captures only)."},
				},
				"required": []string{"source", "out"},
			},
		},
		"scaffold": {
			"description": "Scaffold client_gen.go, stateful port.go, contract.yaml, and TASK.md from a Golden Fixture.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"fixture": map[string]any{"type": "string"},
					"out":     map[string]any{"type": "string"},
					"force":   map[string]any{"type": "boolean"},
				},
				"required": []string{"fixture", "out"},
			},
		},
		"diff": {
			"description": "Compile and run port.go through LoopbackProxy (or compare actual_fixture) with 6-layer surgical wire diff.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"unit":             unitArg,
					"actual_fixture":   map[string]any{"type": "string", "description": "Optional pre-captured actual fixture path; omits live port.go execution when provided."},
					"strict_transport": map[string]any{"type": "boolean"},
					"include_response": map[string]any{"type": "boolean"},
				},
				"required": []string{"unit"},
			},
		},
		"gate": {
			"description": "Evaluate definition of done: compile & run port.go, gofmt, go vet, go test, no-stubs, secret-hygiene, freshness, contract, 6-layer diff, positive assertions, and coverage honesty.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"unit":             unitArg,
					"skip_go_checks":   map[string]any{"type": "boolean"},
					"strict_transport": map[string]any{"type": "boolean"},
					"include_response": map[string]any{"type": "boolean"},
				},
				"required": []string{"unit"},
			},
		},
		"flow_replay": {
			"description": "Execute or resume a stateful multi-step flow DAG from flow.yaml or a saved portable snapshot step.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"flow_dir":   map[string]any{"type": "string"},
					"step":       map[string]any{"type": "string"},
					"oracle_rpc": map[string]any{"type": "string", "description": "Optional external NativeOracle HTTP RPC endpoint."},
				},
				"required": []string{"flow_dir"},
			},
		},
		"analyze": {
			"description": "Analyze fixtures for dependency waves, risks, and 7-scenario matrix classification.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"fixtures_dir": map[string]any{"type": "string"}},
				"required":   []string{"fixtures_dir"},
			},
		},
		"refresh": {
			"description": "Regenerate client_gen.go and pinned_gen.go from port.go AST without modifying port.go.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"unit": unitArg},
				"required":   []string{"unit"},
			},
		},
		"fuzz": {
			"description": "Generate deterministic edge-case query/encoding traps.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"unit": unitArg, "cases": map[string]any{"type": "integer"}, "seed": map[string]any{"type": "integer"}},
				"required":   []string{"unit"},
			},
		},
		"shadow": {
			"description": "Generate shadow_gen.go supporting REQUEST_ANYTHING_MODE=old|shadow|new.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"unit": unitArg},
				"required":   []string{"unit"},
			},
		},
		"report": {
			"description": "Write REPORT.md and card.svg.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"unit": unitArg, "out": map[string]any{"type": "string"}},
				"required":   []string{"unit"},
			},
		},
		"map": {
			"description": "List all scaffolded request units in repo and detect stale upstream recordings.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"repo": map[string]any{"type": "string"}, "write": map[string]any{"type": "boolean"}},
				"required":   []string{"repo"},
			},
		},
		"go": {
			"description": "Run autonomous headless agent port-and-gate loop up to N rounds.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"unit": unitArg, "agent": map[string]any{"type": "string"}, "rounds": map[string]any{"type": "integer"}},
				"required":   []string{"unit"},
			},
		},
	}

	out := make([]map[string]any, 0, len(toolMetas))
	for _, m := range toolMetas {
		entry := map[string]any{
			"name":  m.Name,
			"title": m.Title,
			"annotations": map[string]any{
				"title":           m.Title,
				"readOnlyHint":    m.ReadOnly,
				"destructiveHint": m.Destructive,
				"idempotentHint":  m.Idempotent,
				"openWorldHint":   m.OpenWorld,
			},
		}
		for k, v := range schemas[m.Name] {
			entry[k] = v
		}
		out = append(out, entry)
	}
	return out
}

// CallTool dispatches one MCP tools/call execution.
func CallTool(ctx context.Context, name string, args map[string]any) (any, error) {
	reqStr := func(key string) (string, error) {
		v, ok := args[key].(string)
		if !ok || strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("missing `%s`", key)
		}
		return v, nil
	}
	absPath := func(key string) (string, error) {
		s, err := reqStr(key)
		if err != nil {
			return "", err
		}
		return filepath.Abs(s)
	}

	switch name {
	case "test_sleep":
		ms, _ := args["ms"].(float64)
		timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return map[string]any{"slept": true}, nil
		}
	case "import":
		src, err := reqStr("source")
		if err != nil {
			return nil, err
		}
		outDir, err := absPath("out")
		if err != nil {
			return nil, err
		}
		keep, _ := args["keep_secrets"].(bool)
		format, _ := args["format"].(string)
		keylog, _ := args["keylog"].(string)
		fixes, err := ImportAutoWithKeylog(src, format, keylog)
		if err != nil {
			return nil, err
		}
		saved := make([]string, 0, len(fixes))
		for _, f := range fixes {
			fp, _, serr := ingest.SaveFixture(outDir, f, redact.Options{KeepSecrets: keep})
			if serr != nil {
				return nil, serr
			}
			saved = append(saved, fp)
		}
		return map[string]any{"count": len(saved), "fixtures": saved}, nil
	case "scaffold":
		fixFile, err := absPath("fixture")
		if err != nil {
			return nil, err
		}
		outDir, err := absPath("out")
		if err != nil {
			return nil, err
		}
		fix, err := ingest.LoadFixture(fixFile)
		if err != nil {
			return nil, err
		}
		force, _ := args["force"].(bool)
		return scaffold.Scaffold(scaffold.Options{Root: filepath.Dir(outDir), OutDir: outDir, Fixture: fix, Force: force})
	case "refresh":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		if err := scaffold.Refresh(unitDir); err != nil {
			return nil, err
		}
		return map[string]any{"refreshed": true, "unit": unitDir}, nil
	case "diff":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		manBytes, err := os.ReadFile(filepath.Join(unitDir, scaffold.ManifestFile))
		if err != nil {
			return nil, err
		}
		var man models.UnitManifest
		if err := json.Unmarshal(manBytes, &man); err != nil {
			return nil, err
		}
		expFix, err := ingest.LoadFixture(filepath.Join(unitDir, filepath.FromSlash(man.FixtureFile)))
		if err != nil {
			return nil, err
		}
		var actReq *models.WireRequest
		var actResp *models.WireResponse
		if actPath, ok := args["actual_fixture"].(string); ok && actPath != "" {
			af, err := ingest.LoadFixture(actPath)
			if err != nil {
				return nil, err
			}
			actReq = &af.Request
			actResp = af.Response
		} else {
			runRes, _, _, cerr := unitexec.CaptureUnit(ctx, unitDir)
			if cerr != nil {
				return nil, cerr
			}
			if len(runRes.Requests) == 0 {
				return nil, fmt.Errorf("port.go executed 0 wire requests through LoopbackProxy (%v: %s)", runRes.Err, runRes.Output)
			}
			actReq = runRes.Requests[0]
			if len(runRes.Responses) > 0 {
				actResp = runRes.Responses[0]
			}
		}
		spec, _ := contract.Load(unitDir)
		strict, _ := args["strict_transport"].(bool)
		includeResp, _ := args["include_response"].(bool)
		return diff.CompareRequests(ctx, expFix.ID, &expFix.Request, actReq, expFix.Response, actResp, diff.Options{
			Contract:        spec,
			StrictTransport: strict,
			IncludeResponse: includeResp,
		}), nil
	case "gate":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		skipGo, _ := args["skip_go_checks"].(bool)
		strict, _ := args["strict_transport"].(bool)
		includeResp, _ := args["include_response"].(bool)
		gOpts := gate.Options{
			UnitDir:         unitDir,
			SkipGoChecks:    skipGo,
			StrictTransport: strict,
			IncludeResponse: includeResp,
		}
		if actPath, ok := args["actual_fixture"].(string); ok && actPath != "" {
			af, err := ingest.LoadFixture(actPath)
			if err != nil {
				return nil, err
			}
			gOpts.ActualRequests = []*models.WireRequest{&af.Request}
			if af.Response != nil {
				gOpts.ActualResponses = []*models.WireResponse{af.Response}
			}
			gOpts.ReqIDCorrelated = true
		}
		return gate.Evaluate(ctx, gOpts)
	case "flow_replay":
		flowDir, err := absPath("flow_dir")
		if err != nil {
			return nil, err
		}
		spec, err := flow.LoadFlow(flowDir)
		if err != nil {
			return nil, err
		}
		stepID, _ := args["step"].(string)
		rpcURL, _ := args["oracle_rpc"].(string)
		runner := &flow.Runner{
			FlowDir:  flowDir,
			Executor: flow.DefaultHTTPExecutor(spec.BaseURL),
		}
		needsOracle := rpcURL != ""
		for _, s := range spec.Steps {
			if s.SignWithOracle {
				needsOracle = true
				break
			}
		}
		if needsOracle {
			so, h, closeFn, oerr := flow.OpenDefaultOracle(ctx, rpcURL)
			if oerr != nil {
				return nil, oerr
			}
			defer closeFn()
			runner.Oracle = so
			runner.Handle = h
		}
		return runner.Run(ctx, spec, stepID, nil)
	case "analyze":
		dir, err := absPath("fixtures_dir")
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		var fixes []*models.GoldenFixture
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".fixture.json") {
				if f, ferr := ingest.LoadFixture(filepath.Join(dir, e.Name())); ferr == nil {
					fixes = append(fixes, f)
				}
			}
		}
		return analyze.AnalyzeFixtures(fixes), nil
	case "fuzz":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		cases := 20
		if c, ok := args["cases"].(float64); ok && c > 0 {
			cases = int(c)
		}
		var seed uint64
		if s, ok := args["seed"].(float64); ok && s > 0 {
			seed = uint64(s)
		}
		return fuzz.Run(ctx, fuzz.Options{UnitDir: unitDir, Cases: cases, Seed: seed})
	case "shadow":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		manBytes, err := os.ReadFile(filepath.Join(unitDir, scaffold.ManifestFile))
		if err != nil {
			return nil, err
		}
		var man models.UnitManifest
		if err := json.Unmarshal(manBytes, &man); err != nil {
			return nil, err
		}
		path, err := shadow.Generate(unitDir, man)
		if err != nil {
			return nil, err
		}
		return map[string]any{"path": path}, nil
	case "report":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		outDir, _ := args["out"].(string)
		return report.MeasureAndWriteReport(ctx, unitDir, outDir)
	case "map":
		repo, err := absPath("repo")
		if err != nil {
			return nil, err
		}
		writeMD, _ := args["write"].(bool)
		return report.BuildPortMap(repo, writeMD, false)
	case "go":
		unitDir, err := absPath("unit")
		if err != nil {
			return nil, err
		}
		agent, _ := args["agent"].(string)
		rounds := 3
		if r, ok := args["rounds"].(float64); ok && r > 0 {
			rounds = int(r)
		}
		return auto.Run(ctx, auto.Options{UnitDir: unitDir, Agent: agent, Rounds: rounds})
	default:
		return nil, fmt.Errorf("unknown tool `%s`", name)
	}
}

// ImportAuto parses cURL, HAR, SQLite, Frida JSON, raw HTTP, .mitm, or PCAP based on format/extension.
func ImportAuto(source, format string) ([]*models.GoldenFixture, error) {
	return ImportAutoWithKeylog(source, format, "")
}

// ImportAutoWithKeylog parses supported capture formats with optional SSLKEYLOGFILE for PCAP decryption.
func ImportAutoWithKeylog(source, format, keylog string) ([]*models.GoldenFixture, error) {
	fmtLower := strings.ToLower(format)
	if fmtLower == "" || fmtLower == "auto" {
		low := strings.ToLower(source)
		switch {
		case strings.HasPrefix(strings.TrimSpace(low), "curl "):
			fmtLower = "curl"
		case strings.HasSuffix(low, ".har"):
			fmtLower = "har"
		case strings.HasSuffix(low, ".sqlite"), strings.HasSuffix(low, ".sqlite3"), strings.HasSuffix(low, ".db"):
			fmtLower = "sqlite"
		case strings.HasSuffix(low, ".mitm"):
			fmtLower = "mitm"
		case strings.HasSuffix(low, ".pcap"), strings.HasSuffix(low, ".pcapng"):
			fmtLower = "pcap"
		case strings.HasSuffix(low, ".json"), strings.HasSuffix(low, ".jsonl"), strings.HasSuffix(low, ".ndjson"):
			fmtLower = "frida"
		default:
			fmtLower = "raw"
		}
	}
	switch fmtLower {
	case "curl":
		raw := source
		if data, err := os.ReadFile(source); err == nil {
			raw = string(data)
		}
		f, err := ingest.ParseCurl(raw, "")
		if err != nil {
			return nil, err
		}
		return []*models.GoldenFixture{f}, nil
	case "har":
		return ingest.ParseHAR(source)
	case "sqlite":
		return ingest.ParseSQLite(source)
	case "frida":
		return ingest.ParseFridaJSON(source)
	case "mitm":
		return ingest.ParseMITMFile(source)
	case "pcap":
		return ingest.ParsePCAPWithSSLKeyLog(source, keylog)
	case "raw":
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		f, err := ingest.ParseRawHTTP(data, "https", "")
		if err != nil {
			return nil, err
		}
		return []*models.GoldenFixture{f}, nil
	default:
		return nil, fmt.Errorf("unsupported import format %q", format)
	}
}

// ClassifyFailure maps tool errors into structured codes matching rust-anything/src/mcp.rs.
func ClassifyFailure(msg string, args map[string]any) map[string]any {
	target := "<unit>"
	for _, k := range []string{"unit", "flow_dir", "repo"} {
		if s, ok := args[k].(string); ok && s != "" {
			target = s
			break
		}
	}
	code := "failed"
	retryable := false
	var next any

	switch {
	case strings.Contains(msg, "timed out"):
		code = "timed_out"
		retryable = true
		next = "retry with a larger timeout"
	case strings.Contains(msg, "no such file") || strings.Contains(msg, "no fixture"):
		code = "no_recording"
		next = "request-anything import --source <capture> --out " + target
	case strings.Contains(msg, "changed since it was recorded"):
		code = "stale_recording"
		next = "request-anything refresh " + target
	case strings.Contains(msg, "silent ignore"):
		code = "contract_incomplete"
		next = "add explicit reason or remove ignore in contract.yaml"
	case strings.Contains(msg, "stalled"):
		code = "stalled"
		next = "stop editing and review remaining mismatches with user"
	case strings.Contains(msg, "worker unhealthy") || strings.Contains(msg, "oracle"):
		code = "oracle_unhealthy"
		next = "check NativeOracle sidecar health and logs"
	case strings.HasPrefix(msg, "missing `") && !strings.Contains(msg, "\n"):
		code = "invalid_arguments"
	case strings.HasPrefix(msg, "unknown tool `"):
		code = "unknown_tool"
		next = "call tools/list for supported tools"
	}
	return map[string]any{
		"code":      code,
		"message":   msg,
		"retryable": retryable,
		"next":      next,
	}
}

func rpcResult(id any, res any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": res}
}

func rpcError(id any, code int, msg string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	}
}

func progressNotification(tok any, done int, msg string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/progress",
		"params": map[string]any{
			"progressToken": tok,
			"progress":      done,
			"total":         1,
			"message":       msg,
		},
	}
}

func extractProgressToken(params map[string]any) any {
	meta, ok := params["_meta"].(map[string]any)
	if !ok {
		return nil
	}
	tok := meta["progressToken"]
	switch tok.(type) {
	case string, float64, int, int64:
		return tok
	default:
		return nil
	}
}

func canonicalID(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
