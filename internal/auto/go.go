package auto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TaTrap/request-anything/internal/contract"
	"github.com/TaTrap/request-anything/internal/gate"
	"github.com/TaTrap/request-anything/internal/models"
	"github.com/TaTrap/request-anything/internal/process"
)

// Options configures the autonomous headless agent loop (`request-anything go --agent ...`).
type Options struct {
	UnitDir string
	Agent   string // claude | codex | custom command
	Rounds  int
}

// Outcome reports the final autonomous loop stage.
type Outcome struct {
	Stage        string   `json:"stage"` // waiting_for_port | stalled | gate_failed | passed
	RoundsUsed   int      `json:"rounds_used"`
	FailedChecks []string `json:"failed_checks,omitempty"`
}

// Run executes the build-diff-gate-agent loop up to Rounds turns, stopping immediately if stalled.
func Run(ctx context.Context, opts Options) (*Outcome, error) {
	if opts.Rounds <= 0 {
		opts.Rounds = 3
	}
	absDir, err := filepath.Abs(opts.UnitDir)
	if err != nil {
		return nil, err
	}
	taskBytes, err := os.ReadFile(filepath.Join(absDir, contract.TaskFile))
	if err != nil {
		return nil, fmt.Errorf("missing %s: %w", contract.TaskFile, err)
	}
	prompt := string(taskBytes)

	for round := 0; round <= opts.Rounds; round++ {
		out, gErr := gate.Evaluate(ctx, gate.Options{UnitDir: absDir, SkipGoChecks: false})
		if gErr == nil && out.Passed {
			return &Outcome{Stage: "passed", RoundsUsed: round}, nil
		}
		if gErr == nil && out.Trend != nil && out.Trend.Stalled {
			return &Outcome{
				Stage:        "stalled",
				RoundsUsed:   round,
				FailedChecks: failedNames(out),
			}, nil
		}
		if opts.Agent == "" {
			return &Outcome{
				Stage:        "waiting_for_port",
				RoundsUsed:   round,
				FailedChecks: failedNames(out),
			}, nil
		}
		if round == opts.Rounds {
			return &Outcome{
				Stage:        "gate_failed",
				RoundsUsed:   round,
				FailedChecks: failedNames(out),
			}, nil
		}
		prog, args, stdin := agentInvocation(opts.Agent, prompt)
		if _, rErr := process.Run(ctx, absDir, process.BuildTimeout, stdin, nil, prog, args...); rErr != nil {
			return nil, fmt.Errorf("agent %q failed on round %d: %w", opts.Agent, round+1, rErr)
		}
		if out != nil {
			prompt = string(taskBytes) + "\n\nFix these remaining gate failures:\n- " + strings.Join(failedNames(out), "\n- ")
		}
	}
	return &Outcome{Stage: "gate_failed", RoundsUsed: opts.Rounds}, nil
}

func agentInvocation(agent, prompt string) (string, []string, []byte) {
	fields := strings.Fields(agent)
	if len(fields) == 0 {
		return "claude", []string{"-p"}, []byte(prompt)
	}
	if len(fields) == 1 {
		switch strings.ToLower(fields[0]) {
		case "claude":
			return "claude", []string{"-p", "--permission-mode", "acceptEdits"}, []byte(prompt)
		case "codex":
			return "codex", []string{"exec", "--full-auto", "-"}, []byte(prompt)
		case "kimi", "kimi-code", "kimi-cli":
			return "kimi", []string{"--auto", "-p", prompt}, nil
		}
	}
	return fields[0], fields[1:], []byte(prompt)
}

func failedNames(out *models.GateOutcome) []string {
	if out == nil {
		return nil
	}
	var names []string
	for _, c := range out.Checks {
		if !c.Passed {
			names = append(names, fmt.Sprintf("%s: %s", c.Name, c.Detail))
		}
	}
	return names
}
