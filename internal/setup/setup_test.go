package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TaTrap/request-anything/pkg/wireclient"
)

func TestSetupPreservesKeyOrderCreatesBackupAndRemovesCleanly(t *testing.T) {
	home := t.TempDir()
	claudeCfg := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(claudeCfg, []byte(`{"zeta":1,"mcpServers":{"other":{"command":"x"}},"alpha":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Setup(Options{
		Home:    home,
		Agents:  []Agent{AgentClaude, AgentCodex, AgentOpenCode},
		Command: "/opt/bin/request-anything",
		Backup:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes) == 0 {
		t.Fatalf("expected setup changes")
	}
	if _, err := os.Stat(claudeCfg + ".request-anything.bak"); err != nil {
		t.Fatalf("expected backup file: %v", err)
	}

	// Key order must survive intact (`zeta`, `mcpServers`, `alpha`)
	data, _ := os.ReadFile(claudeCfg)
	val, err := wireclient.UnmarshalOrdered(data)
	if err != nil {
		t.Fatal(err)
	}
	om := val.(*wireclient.OrderedMap)
	if om.Pairs[0].Key != "zeta" || om.Pairs[1].Key != "mcpServers" || om.Pairs[2].Key != "alpha" {
		t.Fatalf("key order corrupted: %+v", om.Pairs)
	}

	// Remove restores cleanly without touching other servers
	if _, err := Setup(Options{
		Home:   home,
		Agents: []Agent{AgentClaude, AgentCodex, AgentOpenCode},
		Remove: true,
	}); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(claudeCfg)
	if string(data2) == "" {
		t.Fatal("empty config after remove")
	}
}

func TestNormalizeAgentAliases(t *testing.T) {
	cases := map[string]Agent{
		"kimi":        AgentKimi,
		"kimi-code":   AgentKimi,
		"KIMI-CLI":    AgentKimi,
		"agy":         AgentAntigravity,
		"antigravity": AgentAntigravity,
		"claude":      AgentClaude,
	}
	for raw, want := range cases {
		got, err := NormalizeAgent(raw)
		if err != nil || got != want {
			t.Fatalf("NormalizeAgent(%q) = (%v, %v), want (%v, nil)", raw, got, err, want)
		}
	}
	if _, err := NormalizeAgent("unknown-agent"); err == nil {
		t.Fatalf("expected error for unknown agent")
	}
}

func TestSetupKimiAndAntigravityGlobalConfigAndSkills(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kimi-code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "config"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Auto-detect should pick up both AgentKimi (.kimi-code) and AgentAntigravity (.gemini/config) + AgentGemini (.gemini)
	rep, err := Setup(Options{
		Home:    home,
		Command: "C:/bin/request-anything.exe",
		Backup:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes) == 0 {
		t.Fatalf("expected auto-detected changes for kimi and antigravity")
	}

	kimiMCP := filepath.Join(home, ".kimi-code", "mcp.json")
	kimiBytes, err := os.ReadFile(kimiMCP)
	if err != nil {
		t.Fatalf("expected %s created: %v", kimiMCP, err)
	}
	if !strings.Contains(string(kimiBytes), `"request-anything"`) || !strings.Contains(string(kimiBytes), `"mcp"`) {
		t.Fatalf("unexpected Kimi mcp.json content:\n%s", kimiBytes)
	}
	if strings.Contains(string(kimiBytes), `"stdio"`) {
		t.Fatalf("Kimi mcp.json should not force Claude-only stdio type:\n%s", kimiBytes)
	}

	kimiSkill := filepath.Join(home, ".kimi-code", "skills", AppName, "SKILL.md")
	if _, err := os.Stat(kimiSkill); err != nil {
		t.Fatalf("expected Kimi skill installed at %s: %v", kimiSkill, err)
	}

	agyMCP := filepath.Join(home, ".gemini", "config", "mcp_config.json")
	agyBytes, err := os.ReadFile(agyMCP)
	if err != nil {
		t.Fatalf("expected Antigravity config at %s: %v", agyMCP, err)
	}
	if !strings.Contains(string(agyBytes), `"request-anything"`) {
		t.Fatalf("unexpected Antigravity mcp_config.json:\n%s", agyBytes)
	}

	agySkill := filepath.Join(home, ".gemini", "config", "skills", AppName, "SKILL.md")
	if _, err := os.Stat(agySkill); err != nil {
		t.Fatalf("expected Antigravity skill at %s: %v", agySkill, err)
	}

	// Verify legacy ~/.kimi fallback when only ~/.kimi exists
	legacyHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(legacyHome, ".kimi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(Options{Home: legacyHome, Command: "/usr/local/bin/request-anything"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(legacyHome, ".kimi", "mcp.json")); err != nil {
		t.Fatalf("expected legacy ~/.kimi/mcp.json fallback: %v", err)
	}
}

func TestSetupGlobalBinInstallIdempotentAndRemove(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kimi-code"), 0o755); err != nil {
		t.Fatal(err)
	}
	srcExe := filepath.Join(t.TempDir(), "built-request-anything.bin")
	if err := os.WriteFile(srcExe, []byte("dummy-executable-v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	// First install: copies srcExe into ~/.local/bin and points MCP config to it
	rep1, err := Setup(Options{
		Home:       home,
		InstallBin: true,
		SourceExe:  srcExe,
	})
	if err != nil {
		t.Fatal(err)
	}
	dstBin := GlobalBinPath(home)
	if rep1.Command != dstBin {
		t.Fatalf("expected global command %q, got %q", dstBin, rep1.Command)
	}
	gotBytes, err := os.ReadFile(dstBin)
	if err != nil || string(gotBytes) != "dummy-executable-v1" {
		t.Fatalf("expected copied global binary at %s: err=%v", dstBin, err)
	}
	if len(rep1.Changes) == 0 || rep1.Changes[0].Agent != "global-bin" || rep1.Changes[0].Action != "added" {
		t.Fatalf("expected first global-bin change added, got %+v", rep1.Changes)
	}
	if _, err := os.Stat(ModRootStatePath(home)); err != nil {
		t.Fatalf("expected modroot pointer saved: %v", err)
	}

	// Verify Kimi mcp.json points to dstBin
	mcpData, _ := os.ReadFile(filepath.Join(home, ".kimi-code", "mcp.json"))
	if !strings.Contains(string(mcpData), filepath.Base(dstBin)) {
		t.Fatalf("expected mcp.json to reference %s:\n%s", dstBin, mcpData)
	}

	// Second install: identical bytes -> unchanged
	rep2, err := Setup(Options{
		Home:       home,
		InstallBin: true,
		SourceExe:  srcExe,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep2.Changes {
		if ch.Action != "unchanged" {
			t.Fatalf("expected idempotent unchanged on 2nd setup, got %+v", ch)
		}
	}

	// Remove cleans global binary, modroot pointer, and MCP/skills
	rep3, err := Setup(Options{
		Home:       home,
		InstallBin: true,
		Remove:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dstBin); !os.IsNotExist(err) {
		t.Fatalf("expected global binary removed")
	}
	if _, err := os.Stat(ModRootStatePath(home)); !os.IsNotExist(err) {
		t.Fatalf("expected modroot pointer removed")
	}
	if rep3.Changes[0].Agent != "global-bin" || rep3.Changes[0].Action != "removed" {
		t.Fatalf("expected global-bin removed, got %+v", rep3.Changes[0])
	}
}
