package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/TaTrap/request-anything/internal/analyze"
	"github.com/TaTrap/request-anything/internal/auto"
	"github.com/TaTrap/request-anything/internal/capture"
	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/diff"
	"github.com/TaTrap/request-anything/internal/doctor"
	"github.com/TaTrap/request-anything/internal/flow"
	"github.com/TaTrap/request-anything/internal/fuzz"
	"github.com/TaTrap/request-anything/internal/ingest"
	"github.com/TaTrap/request-anything/internal/mcp"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/redact"
	"github.com/TaTrap/request-anything/internal/report"
	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/internal/setup"
	"github.com/TaTrap/request-anything/internal/shadow"
	"github.com/spf13/cobra"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var jsonOut bool
	rootCmd := &cobra.Command{
		Use:     "request-anything",
		Version: mcp.Version,
		Short:   "Port HTTP/HTTPS/HTTP2/Protobuf API requests and stateful flows to Go with Wire-Level Ground Truth",
	}
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "Print machine-readable JSON output")

	printResult := func(v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	}

	// import
	var impFmt, impOut, impKeylog string
	var impKeepSecrets bool
	importCmd := &cobra.Command{
		Use:   "import <source>",
		Short: "Import cURL, HAR, gzipped capture SQLite, Frida JSON, raw HTTP, .mitm, or PCAP into Golden Fixtures",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir, err := filepath.Abs(impOut)
			if err != nil {
				return err
			}
			src := args[0]
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(src)), "curl ") {
				if abs, aerr := filepath.Abs(src); aerr == nil {
					src = abs
				}
			}
			fixes, err := mcp.ImportAutoWithKeylog(src, impFmt, impKeylog)
			if err != nil {
				return err
			}
			var saved []string
			for _, f := range fixes {
				fp, _, serr := ingest.SaveFixture(outDir, f, redact.Options{KeepSecrets: impKeepSecrets})
				if serr != nil {
					return serr
				}
				saved = append(saved, fp)
			}
			if jsonOut {
				printResult(map[string]any{"count": len(saved), "fixtures": saved})
			} else {
				fmt.Printf("Imported %d fixture(s) into %s\n", len(saved), outDir)
			}
			return nil
		},
	}
	importCmd.Flags().StringVar(&impFmt, "format", "auto", "Input format: auto|curl|har|sqlite|frida|raw|mitm|pcap")
	importCmd.Flags().StringVarP(&impOut, "out", "o", "./fixtures", "Output fixture directory")
	importCmd.Flags().StringVar(&impKeylog, "keylog", "", "Optional SSLKEYLOGFILE path for .pcap/.pcapng decryption")
	importCmd.Flags().BoolVar(&impKeepSecrets, "keep-secrets", false, "Disable default secret redaction")

	// analyze
	analyzeCmd := &cobra.Command{
		Use:   "analyze <fixtures-dir>",
		Short: "Analyze fixtures for dependency waves, risks, and scenario matrix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			var fixes []*models.GoldenFixture
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".fixture.json") {
					if f, ferr := ingest.LoadFixture(filepath.Join(dir, e.Name())); ferr == nil {
						fixes = append(fixes, f)
					}
				}
			}
			rep := analyze.AnalyzeFixtures(fixes)
			printResult(rep)
			return nil
		},
	}

	// scaffold
	var scafOut, scafPkg string
	var scafForce, scafStub, scafPin bool
	scaffoldCmd := &cobra.Command{
		Use:   "scaffold <fixture.json>",
		Short: "Scaffold client_gen.go, port.go, contract.yaml, and TASK.md",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fixPath, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			outDir, err := filepath.Abs(scafOut)
			if err != nil {
				return err
			}
			fix, err := ingest.LoadFixture(fixPath)
			if err != nil {
				return err
			}
			out, err := scaffold.Scaffold(scaffold.Options{
				Root:        filepath.Dir(outDir),
				OutDir:      outDir,
				Fixture:     fix,
				PackageName: scafPkg,
				StubPort:    scafStub,
				PinClock:    scafPin,
				Force:       scafForce,
			})
			if err != nil {
				return err
			}
			printResult(out)
			return nil
		},
	}
	scaffoldCmd.Flags().StringVarP(&scafOut, "out", "o", "./port_unit", "Output Go unit folder")
	scaffoldCmd.Flags().StringVar(&scafPkg, "pkg", "", "Go package name")
	scaffoldCmd.Flags().BoolVar(&scafForce, "force", false, "Overwrite existing unit")
	scaffoldCmd.Flags().BoolVar(&scafStub, "stub", false, "Generate todo panic stubs in port.go")
	scaffoldCmd.Flags().BoolVar(&scafPin, "pin-clock", true, "Create pinned.json")

	// refresh
	refreshCmd := &cobra.Command{
		Use:   "refresh <unit-dir>",
		Short: "Regenerate client_gen.go and pinned_gen.go without touching port.go",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if err := scaffold.Refresh(dir); err != nil {
				return err
			}
			fmt.Printf("Refreshed %s\n", dir)
			return nil
		},
	}

	// diff
	var diffActual string
	var diffStrict, diffIncResp bool
	diffCmd := &cobra.Command{
		Use:   "diff <unit-dir>",
		Short: "Compile & run port.go against LoopbackProxy and diff all 6 wire layers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			res, err := mcp.CallTool(ctx, "diff", map[string]any{
				"unit":             dir,
				"actual_fixture":   diffActual,
				"strict_transport": diffStrict,
				"include_response": diffIncResp,
			})
			if err != nil {
				return err
			}
			printResult(res)
			if dr, ok := res.(*models.DiffResult); ok && !dr.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
	diffCmd.Flags().StringVar(&diffActual, "actual", "", "Optional actual captured fixture to compare")
	diffCmd.Flags().BoolVar(&diffStrict, "strict-transport", false, "Enforce L5 strict JA4/H2 SETTINGS checks")
	diffCmd.Flags().BoolVar(&diffIncResp, "include-response", false, "Compare L6 response status and decoded body")

	// gate
	var gateSkipGo, gateStrict, gateIncResp bool
	gateCmd := &cobra.Command{
		Use:   "gate <unit-dir>",
		Short: "Run Hard Gate checks including live port.go execution, positive-assertions, and coverage honesty",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			res, err := mcp.CallTool(ctx, "gate", map[string]any{
				"unit":             dir,
				"skip_go_checks":   gateSkipGo,
				"strict_transport": gateStrict,
				"include_response": gateIncResp,
			})
			if err != nil {
				return err
			}
			printResult(res)
			if g, ok := res.(*models.GateOutcome); ok && !g.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
	gateCmd.Flags().BoolVar(&gateSkipGo, "skip-go-checks", false, "Skip gofmt/go vet/go test subprocesses")
	gateCmd.Flags().BoolVar(&gateStrict, "strict-transport", false, "Enforce L5 strict JA4/H2 SETTINGS checks")
	gateCmd.Flags().BoolVar(&gateIncResp, "include-response", false, "Compare L6 response status and decoded body")

	// capture (runs live loopback diff proxy until Ctrl+C)
	captureCmd := &cobra.Command{
		Use:   "capture",
		Short: "Start live raw HTTP/1.1 + 9-byte HTTP/2 + TLS ClientHello loopback proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := capture.StartLoopbackProxy(nil)
			if err != nil {
				return err
			}
			defer p.Close()
			fmt.Fprintf(os.Stderr, "Listening on %s (Ctrl+C to stop)\n", p.URL())
			<-ctx.Done()
			printResult(p.Captured())
			return nil
		},
	}

	// flow
	var flowStep, flowOracleRPC string
	flowCmd := &cobra.Command{Use: "flow", Short: "Multi-step stateful DAG flow operations"}
	flowReplayCmd := &cobra.Command{
		Use:   "replay <flow-dir>",
		Short: "Replay flow.yaml (or resume from --step snapshot)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			res, err := mcp.CallTool(ctx, "flow_replay", map[string]any{
				"flow_dir":   dir,
				"step":       flowStep,
				"oracle_rpc": flowOracleRPC,
			})
			if err != nil {
				return err
			}
			printResult(res)
			if out, ok := res.(*flow.FlowOutcome); ok && !out.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
	flowReplayCmd.Flags().StringVar(&flowStep, "step", "", "Step ID to restore from snapshot and resume")
	flowReplayCmd.Flags().StringVar(&flowOracleRPC, "oracle-rpc", "", "Optional external NativeOracle HTTP RPC endpoint")

	flowLiftCmd := &cobra.Command{
		Use:   "lift <flow-dir>",
		Short: "Verify 0% fallback across flow replay and write LIFTED.md",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			res, err := mcp.CallTool(ctx, "flow_replay", map[string]any{
				"flow_dir":   dir,
				"oracle_rpc": flowOracleRPC,
			})
			if err != nil {
				return err
			}
			out, ok := res.(*flow.FlowOutcome)
			if !ok {
				return fmt.Errorf("unexpected flow replay result type %T", res)
			}
			if err := flow.LiftFlow(dir, out); err != nil {
				return err
			}
			printResult(out)
			return nil
		},
	}
	flowLiftCmd.Flags().StringVar(&flowOracleRPC, "oracle-rpc", "", "Optional external NativeOracle HTTP RPC endpoint")
	flowCmd.AddCommand(flowReplayCmd, flowLiftCmd)

	// fuzz, shadow, report, map, go, mcp, setup, doctor
	var fuzzCases int
	var fuzzSeed uint64
	var fuzzKeep string
	fuzzCmd := &cobra.Command{
		Use:   "fuzz <unit-dir>",
		Short: "Compile & fuzz port.go against LoopbackProxy with deterministic edge traps",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, _ := filepath.Abs(args[0])
			out, err := fuzz.Run(ctx, fuzz.Options{UnitDir: dir, Cases: fuzzCases, Seed: fuzzSeed, Keep: fuzzKeep})
			if err != nil {
				return err
			}
			printResult(out)
			if out.Mismatches > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	fuzzCmd.Flags().IntVar(&fuzzCases, "cases", 5, "Number of fuzz trap cases to execute")
	fuzzCmd.Flags().Uint64Var(&fuzzSeed, "seed", 0, "Deterministic RNG seed")
	fuzzCmd.Flags().StringVar(&fuzzKeep, "keep", "", "Save cases to fuzz-cases.jsonl: all|mismatches")

	shadowCmd := &cobra.Command{
		Use:   "shadow <unit-dir>",
		Short: "Generate shadow_gen.go (old|shadow|new)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := mcp.CallTool(ctx, "shadow", map[string]any{"unit": args[0]})
			if err != nil {
				return err
			}
			printResult(res)
			return nil
		},
	}

	var reportOut string
	reportCmd := &cobra.Command{
		Use:   "report <unit-dir>",
		Short: "Measure Go port performance & Hard Gate, writing REPORT.md and card.svg",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := mcp.CallTool(ctx, "report", map[string]any{"unit": args[0], "out": reportOut})
			if err != nil {
				return err
			}
			printResult(res)
			return nil
		},
	}
	reportCmd.Flags().StringVar(&reportOut, "out", "", "Output report directory (defaults to <unit-dir>/report)")

	var mapWrite, mapCheck bool
	mapCmd := &cobra.Command{
		Use:   "map [repo]",
		Short: "Map scaffolded request ports across a repository",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo := "."
			if len(args) > 0 {
				repo = args[0]
			}
			pm, err := report.BuildPortMap(repo, mapWrite, mapCheck)
			if err != nil {
				return err
			}
			printResult(pm)
			return nil
		},
	}
	mapCmd.Flags().BoolVar(&mapWrite, "write", false, "Write PORT_MAP.md")
	mapCmd.Flags().BoolVar(&mapCheck, "check", false, "Exit non-zero if any port is stale")

	var goAgent string
	var goRounds int
	goCmd := &cobra.Command{
		Use:   "go <unit-dir>",
		Short: "Autonomous agent loop: port -> diff -> gate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, _ := filepath.Abs(args[0])
			out, err := auto.Run(ctx, auto.Options{UnitDir: dir, Agent: goAgent, Rounds: goRounds})
			if err != nil {
				return err
			}
			printResult(out)
			return nil
		},
	}
	goCmd.Flags().StringVar(&goAgent, "agent", "", "claude | codex | kimi | custom command")
	goCmd.Flags().IntVar(&goRounds, "rounds", 3, "Max agent turns")

	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start stdio JSON-RPC 2.0 MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcp.Serve(ctx)
		},
	}

	var setupRemove, setupDryRun, setupNoBackup, setupNoGlobalBin bool
	var setupAgents []string
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Install user-global binary and register MCP server & skills across coding agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ag []setup.Agent
			for _, s := range setupAgents {
				norm, aerr := setup.NormalizeAgent(s)
				if aerr != nil {
					return aerr
				}
				ag = append(ag, norm)
			}
			rep, err := setup.Setup(setup.Options{
				Agents:     ag,
				InstallBin: !setupNoGlobalBin,
				Remove:     setupRemove,
				DryRun:     setupDryRun,
				Backup:     !setupNoBackup,
			})
			if err != nil {
				return err
			}
			printResult(rep)
			return nil
		},
	}
	setupCmd.Flags().StringSliceVar(&setupAgents, "agent", nil, "Agents: claude,codex,cursor,gemini,opencode,antigravity,kimi")
	setupCmd.Flags().BoolVar(&setupRemove, "remove", false, "Remove installed global binary, MCP & skill entries")
	setupCmd.Flags().BoolVar(&setupDryRun, "dry-run", false, "Preview changes without writing files")
	setupCmd.Flags().BoolVar(&setupNoBackup, "no-backup", false, "Skip .request-anything.bak creation")
	setupCmd.Flags().BoolVar(&setupNoGlobalBin, "no-global-bin", false, "Skip copying binary into ~/.local/bin and register current executable path")

	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check Go toolchain, CA cert, optional capture tools, and MCP self-test",
		RunE: func(cmd *cobra.Command, args []string) error {
			rep := doctor.Run(ctx)
			printResult(rep)
			if !rep.OK {
				os.Exit(1)
			}
			return nil
		},
	}

	// Touch unused imports cleanly
	_ = contract.FileName
	_ = diff.CheckTolerance
	_ = shadow.Generate

	rootCmd.AddCommand(
		importCmd, analyzeCmd, scaffoldCmd, refreshCmd, diffCmd, gateCmd,
		captureCmd, flowCmd, fuzzCmd, shadowCmd, reportCmd, mapCmd,
		goCmd, mcpCmd, setupCmd, doctorCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
