package setup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TaTrap/request-anything/internal/scaffold"
	"github.com/TaTrap/request-anything/pkg/wireclient"
	"github.com/TaTrap/request-anything/skills"
)

const AppName = "request-anything"

// Agent enumerates supported coding agent hosts.
type Agent string

const (
	AgentClaude      Agent = "claude"
	AgentCodex       Agent = "codex"
	AgentCursor      Agent = "cursor"
	AgentGemini      Agent = "gemini"
	AgentOpenCode    Agent = "opencode"
	AgentAntigravity Agent = "antigravity"
	AgentKimi        Agent = "kimi"
)

var AllAgents = []Agent{
	AgentClaude,
	AgentCodex,
	AgentCursor,
	AgentGemini,
	AgentOpenCode,
	AgentAntigravity,
	AgentKimi,
}

// NormalizeAgent resolves user-supplied agent names and aliases cleanly.
func NormalizeAgent(raw string) (Agent, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "claude":
		return AgentClaude, nil
	case "codex":
		return AgentCodex, nil
	case "cursor":
		return AgentCursor, nil
	case "gemini":
		return AgentGemini, nil
	case "opencode":
		return AgentOpenCode, nil
	case "antigravity", "agy":
		return AgentAntigravity, nil
	case "kimi", "kimi-code", "kimi-cli":
		return AgentKimi, nil
	default:
		return "", fmt.Errorf("unknown agent %q; valid: claude, codex, cursor, gemini, opencode, antigravity, kimi", raw)
	}
}

// Options configures agent setup/removal.
type Options struct {
	Home       string
	Agents     []Agent
	Command    string
	InstallBin bool
	SourceExe  string
	Remove     bool
	DryRun     bool
	Backup     bool
}

// Change records one file update performed by setup.
type Change struct {
	Agent  Agent  `json:"agent"`
	File   string `json:"file"`
	Action string `json:"action"` // added | updated | unchanged | removed | absent
	Backup string `json:"backup,omitempty"`
}

// Report summarizes setup actions.
type Report struct {
	Command string   `json:"command"`
	Changes []Change `json:"changes"`
	DryRun  bool     `json:"dry_run"`
}

// DefaultHome returns the user's home folder.
func DefaultHome() (string, error) {
	if h := os.Getenv("HOME"); h != "" {
		return h, nil
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h, nil
	}
	return os.UserHomeDir()
}

// GlobalBinPath returns the user-global binary path inside ~/.local/bin.
func GlobalBinPath(home string) string {
	binName := AppName
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	return filepath.Join(home, ".local", "bin", binName)
}

// ModRootStatePath returns the user-global pointer file recording the source module root.
func ModRootStatePath(home string) string {
	return filepath.Join(home, ".config", AppName, "modroot")
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func resolveKimiDir(home string) string {
	if envDir := strings.TrimSpace(os.Getenv("KIMI_CODE_HOME")); envDir != "" {
		if realHome, err := DefaultHome(); err == nil && filepath.Clean(home) == filepath.Clean(realHome) {
			return envDir
		}
	}
	dotKimiCode := filepath.Join(home, ".kimi-code")
	if isDir(dotKimiCode) {
		return dotKimiCode
	}
	dotKimiLegacy := filepath.Join(home, ".kimi")
	if isDir(dotKimiLegacy) {
		return dotKimiLegacy
	}
	return dotKimiCode
}

// ConfigPath returns the user-global MCP settings file path for an agent.
func ConfigPath(a Agent, home string) string {
	switch a {
	case AgentClaude:
		return filepath.Join(home, ".claude.json")
	case AgentCodex:
		return filepath.Join(home, ".codex", "config.toml")
	case AgentCursor:
		return filepath.Join(home, ".cursor", "mcp.json")
	case AgentGemini:
		return filepath.Join(home, ".gemini", "settings.json")
	case AgentOpenCode:
		return filepath.Join(home, ".config", "opencode", "opencode.json")
	case AgentAntigravity:
		return filepath.Join(home, ".gemini", "config", "mcp_config.json")
	case AgentKimi:
		return filepath.Join(resolveKimiDir(home), "mcp.json")
	default:
		return ""
	}
}

// SkillDir returns the user-global skill install folder for agents that load skills.
func SkillDir(a Agent, home string) string {
	switch a {
	case AgentClaude:
		return filepath.Join(home, ".claude", "skills", AppName)
	case AgentCodex:
		return filepath.Join(home, ".codex", "skills", AppName)
	case AgentGemini:
		return filepath.Join(home, ".gemini", "skills", AppName)
	case AgentOpenCode:
		return filepath.Join(home, ".config", "opencode", "skills", AppName)
	case AgentAntigravity:
		return filepath.Join(home, ".gemini", "config", "skills", AppName)
	case AgentKimi:
		return filepath.Join(resolveKimiDir(home), "skills", AppName)
	default:
		return ""
	}
}

func present(a Agent, home string) bool {
	switch a {
	case AgentClaude:
		return isDir(filepath.Join(home, ".claude"))
	case AgentCodex:
		return isDir(filepath.Join(home, ".codex"))
	case AgentCursor:
		return isDir(filepath.Join(home, ".cursor"))
	case AgentGemini:
		return isDir(filepath.Join(home, ".gemini"))
	case AgentOpenCode:
		return isDir(filepath.Join(home, ".config", "opencode"))
	case AgentAntigravity:
		return isDir(filepath.Join(home, ".gemini", "config")) ||
			isDir(filepath.Join(home, ".gemini", "antigravity-cli")) ||
			isDir(filepath.Join(home, ".gemini", "antigravity"))
	case AgentKimi:
		return isDir(resolveKimiDir(home))
	default:
		return false
	}
}

// Setup installs or removes user-global binary, MCP registration, and workflow skills safely across detected or named agents.
func Setup(opts Options) (*Report, error) {
	home := opts.Home
	if home == "" {
		var err error
		home, err = DefaultHome()
		if err != nil {
			return nil, err
		}
	}
	cmd := opts.Command
	if cmd == "" {
		exe, err := os.Executable()
		if err != nil {
			cmd = AppName
		} else {
			cmd = exe
		}
	}

	targets := opts.Agents
	if len(targets) == 0 {
		for _, a := range AllAgents {
			if present(a, home) {
				targets = append(targets, a)
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no coding agent found under %s; specify --agent claude|codex|cursor|gemini|opencode|antigravity|kimi", home)
	}

	rep := &Report{Command: cmd, DryRun: opts.DryRun}
	if opts.InstallBin && opts.Command == "" {
		binChange, installedPath, err := syncGlobalBinary(home, cmd, opts)
		if err != nil {
			return nil, err
		}
		rep.Changes = append(rep.Changes, binChange)
		if !opts.Remove && installedPath != "" {
			cmd = installedPath
			rep.Command = cmd
		}
	}
	for _, a := range targets {
		cfg := ConfigPath(a, home)
		var ch Change
		var err error
		switch a {
		case AgentCodex:
			ch, err = updateCodexTOML(a, cfg, cmd, opts)
		case AgentOpenCode:
			ch, err = updateOpenCodeJSON(a, cfg, cmd, opts)
		default:
			ch, err = updateStandardJSON(a, cfg, cmd, opts, a == AgentClaude)
		}
		if err != nil {
			return nil, err
		}
		rep.Changes = append(rep.Changes, ch)

		if sDir := SkillDir(a, home); sDir != "" {
			sch, err := syncSkills(a, sDir, opts)
			if err != nil {
				return nil, err
			}
			rep.Changes = append(rep.Changes, sch)
		}
	}
	return rep, nil
}

func updateStandardJSON(a Agent, path, command string, opts Options, stdioType bool) (Change, error) {
	root, existed, err := loadOrderedJSONObject(path)
	if err != nil {
		return Change{}, err
	}
	var servers *wireclient.OrderedMap
	if rawServers, ok := root.Get("mcpServers"); ok {
		sm, isObj := rawServers.(*wireclient.OrderedMap)
		if !isObj {
			return Change{}, fmt.Errorf("`mcpServers` in %s is not a JSON object", path)
		}
		servers = sm
	} else {
		servers = wireclient.NewOrderedMap()
		root.Set("mcpServers", servers)
	}

	action := "unchanged"
	if opts.Remove {
		if deleteOrderedKey(servers, AppName) {
			action = "removed"
		} else {
			action = "absent"
		}
	} else {
		existing, had := servers.Get(AppName)
		entry := wireclient.NewOrderedMap()
		if had {
			if em, ok := existing.(*wireclient.OrderedMap); ok {
				entry = em
			}
		}
		prevBytes, _ := wireclient.MarshalOrdered(entry, wireclient.JSONMarshalOptions{})
		entry.Set("command", command)
		entry.Set("args", []any{"mcp"})
		if stdioType {
			entry.Set("type", "stdio")
		}
		nextBytes, _ := wireclient.MarshalOrdered(entry, wireclient.JSONMarshalOptions{})
		if !had {
			action = "added"
			servers.Set(AppName, entry)
		} else if string(prevBytes) != string(nextBytes) {
			action = "updated"
			servers.Set(AppName, entry)
		}
	}

	var bak string
	if !opts.DryRun && (action == "added" || action == "updated" || action == "removed") {
		if opts.Backup && existed {
			bak, err = createBackup(path)
			if err != nil {
				return Change{}, err
			}
		}
		out, err := wireclient.MarshalOrdered(root, wireclient.JSONMarshalOptions{Indent: "  "})
		if err != nil {
			return Change{}, err
		}
		if err := atomicWrite(path, append(out, '\n')); err != nil {
			return Change{}, err
		}
	}
	return Change{Agent: a, File: path, Action: action, Backup: bak}, nil
}

func updateOpenCodeJSON(a Agent, path, command string, opts Options) (Change, error) {
	root, existed, err := loadOrderedJSONObject(path)
	if err != nil {
		return Change{}, err
	}
	var mcpObj *wireclient.OrderedMap
	if rawMCP, ok := root.Get("mcp"); ok {
		mm, isObj := rawMCP.(*wireclient.OrderedMap)
		if !isObj {
			return Change{}, fmt.Errorf("`mcp` in %s is not a JSON object", path)
		}
		mcpObj = mm
	} else {
		mcpObj = wireclient.NewOrderedMap()
		root.Set("mcp", mcpObj)
	}
	var servers *wireclient.OrderedMap
	if rawSrv, ok := mcpObj.Get("servers"); ok {
		sm, isObj := rawSrv.(*wireclient.OrderedMap)
		if !isObj {
			return Change{}, fmt.Errorf("`mcp.servers` in %s is not a JSON object", path)
		}
		servers = sm
	} else {
		servers = wireclient.NewOrderedMap()
		mcpObj.Set("servers", servers)
	}

	action := "unchanged"
	if opts.Remove {
		if deleteOrderedKey(servers, AppName) {
			action = "removed"
		} else {
			action = "absent"
		}
	} else {
		_, had := servers.Get(AppName)
		entry := wireclient.NewOrderedMap()
		entry.Set("type", "local")
		entry.Set("command", []any{command, "mcp"})
		prev, _ := servers.Get(AppName)
		prevB, _ := wireclient.MarshalOrdered(prev, wireclient.JSONMarshalOptions{})
		nextB, _ := wireclient.MarshalOrdered(entry, wireclient.JSONMarshalOptions{})
		if !had {
			action = "added"
			servers.Set(AppName, entry)
		} else if string(prevB) != string(nextB) {
			action = "updated"
			servers.Set(AppName, entry)
		}
	}

	var bak string
	if !opts.DryRun && (action == "added" || action == "updated" || action == "removed") {
		if opts.Backup && existed {
			bak, err = createBackup(path)
			if err != nil {
				return Change{}, err
			}
		}
		out, err := wireclient.MarshalOrdered(root, wireclient.JSONMarshalOptions{Indent: "  "})
		if err != nil {
			return Change{}, err
		}
		if err := atomicWrite(path, append(out, '\n')); err != nil {
			return Change{}, err
		}
	}
	return Change{Agent: a, File: path, Action: action, Backup: bak}, nil
}

func updateCodexTOML(a Agent, path, command string, opts Options) (Change, error) {
	rawBytes, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Change{}, err
	}
	text := string(rawBytes)
	sectionHeader := "[mcp_servers." + AppName + "]"
	action := "unchanged"
	newText := text

	if opts.Remove {
		if idx := strings.Index(text, sectionHeader); idx >= 0 {
			rest := text[idx+len(sectionHeader):]
			endIdx := len(text)
			if nextSec := strings.Index(rest, "\n["); nextSec >= 0 {
				endIdx = idx + len(sectionHeader) + nextSec + 1
			}
			newText = strings.TrimRight(text[:idx], "\r\n")
			if endIdx < len(text) {
				newText += "\n\n" + text[endIdx:]
			}
			newText = strings.TrimSpace(newText) + "\n"
			action = "removed"
		} else {
			action = "absent"
		}
	} else {
		block := fmt.Sprintf("%s\ncommand = %q\nargs = [\"mcp\"]\n", sectionHeader, command)
		if idx := strings.Index(text, sectionHeader); idx >= 0 {
			rest := text[idx+len(sectionHeader):]
			endIdx := len(text)
			if nextSec := strings.Index(rest, "\n["); nextSec >= 0 {
				endIdx = idx + len(sectionHeader) + nextSec + 1
			}
			oldBlock := strings.TrimSpace(text[idx:endIdx])
			if oldBlock != strings.TrimSpace(block) {
				newText = text[:idx] + block + text[endIdx:]
				action = "updated"
			}
		} else {
			if strings.TrimSpace(text) != "" {
				newText = strings.TrimRight(text, "\r\n") + "\n\n" + block
			} else {
				newText = block
			}
			action = "added"
		}
	}

	var bak string
	if !opts.DryRun && (action == "added" || action == "updated" || action == "removed") {
		if opts.Backup && existed {
			bak, err = createBackup(path)
			if err != nil {
				return Change{}, err
			}
		}
		if err := atomicWrite(path, []byte(newText)); err != nil {
			return Change{}, err
		}
	}
	return Change{Agent: a, File: path, Action: action, Backup: bak}, nil
}

func syncSkills(a Agent, dir string, opts Options) (Change, error) {
	skillPath := filepath.Join(dir, "SKILL.md")
	wholePath := filepath.Join(dir, "whole-flow.md")
	if opts.Remove {
		_, err1 := os.Stat(skillPath)
		_, err2 := os.Stat(wholePath)
		if os.IsNotExist(err1) && os.IsNotExist(err2) {
			return Change{Agent: a, File: skillPath, Action: "absent"}, nil
		}
		if !opts.DryRun {
			_ = os.Remove(skillPath)
			_ = os.Remove(wholePath)
			_ = os.Remove(dir)
		}
		return Change{Agent: a, File: skillPath, Action: "removed"}, nil
	}
	cur1, err1 := os.ReadFile(skillPath)
	cur2, err2 := os.ReadFile(wholePath)
	action := "unchanged"
	if os.IsNotExist(err1) && os.IsNotExist(err2) {
		action = "added"
	} else if string(cur1) != skills.SkillMD || string(cur2) != skills.WholeFlowMD {
		action = "updated"
	}
	if !opts.DryRun && (action == "added" || action == "updated") {
		if err := atomicWrite(skillPath, []byte(skills.SkillMD)); err != nil {
			return Change{}, err
		}
		if err := atomicWrite(wholePath, []byte(skills.WholeFlowMD)); err != nil {
			return Change{}, err
		}
	}
	return Change{Agent: a, File: skillPath, Action: action}, nil
}

func loadOrderedJSONObject(path string) (*wireclient.OrderedMap, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return wireclient.NewOrderedMap(), false, nil
		}
		return nil, false, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return wireclient.NewOrderedMap(), true, nil
	}
	val, err := wireclient.UnmarshalOrdered(data)
	if err != nil {
		return nil, true, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	om, ok := val.(*wireclient.OrderedMap)
	if !ok {
		return nil, true, fmt.Errorf("%s is not a JSON object", path)
	}
	return om, true, nil
}

func deleteOrderedKey(m *wireclient.OrderedMap, key string) bool {
	for i := range m.Pairs {
		if m.Pairs[i].Key == key {
			m.Pairs = append(m.Pairs[:i], m.Pairs[i+1:]...)
			return true
		}
	}
	return false
}

func createBackup(path string) (string, error) {
	bak := path + ".request-anything.bak"
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(bak, data, 0o600); err != nil {
		return "", err
	}
	return bak, nil
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".request-anything.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func syncGlobalBinary(home, currentCmd string, opts Options) (Change, string, error) {
	dstBin := GlobalBinPath(home)
	modPtr := ModRootStatePath(home)

	if opts.Remove {
		_, statErr := os.Stat(dstBin)
		action := "absent"
		if statErr == nil {
			action = "removed"
		}
		if !opts.DryRun {
			if action == "removed" {
				if err := os.Remove(dstBin); err != nil && runtime.GOOS == "windows" {
					_ = os.Remove(dstBin + ".old")
					_ = os.Rename(dstBin, dstBin+".old")
				}
			}
			_ = os.Remove(modPtr)
			_ = os.Remove(filepath.Dir(modPtr))
		}
		return Change{Agent: "global-bin", File: dstBin, Action: action}, "", nil
	}

	srcExe := opts.SourceExe
	if srcExe == "" {
		srcExe = currentCmd
	}
	srcBytes, err := os.ReadFile(srcExe)
	if err != nil {
		return Change{}, "", fmt.Errorf("reading executable %s: %w", srcExe, err)
	}
	dstBytes, dstErr := os.ReadFile(dstBin)
	action := "updated"
	switch {
	case filepath.Clean(srcExe) == filepath.Clean(dstBin):
		action = "unchanged"
	case dstErr == nil && bytes.Equal(srcBytes, dstBytes):
		action = "unchanged"
	case os.IsNotExist(dstErr):
		action = "added"
	}

	if !opts.DryRun {
		if action == "added" || action == "updated" {
			if err := atomicWriteBinary(dstBin, srcBytes); err != nil {
				return Change{}, "", err
			}
		}
		if modRoot, merr := scaffold.FindModuleRoot(); merr == nil && modRoot != "" {
			if err := atomicWrite(modPtr, []byte(modRoot+"\n")); err != nil {
				return Change{}, "", err
			}
		}
	}
	return Change{Agent: "global-bin", File: dstBin, Action: action}, dstBin, nil
}

func atomicWriteBinary(dst string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".request-anything.tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(dst + ".old")
			if rerr := os.Rename(dst, dst+".old"); rerr == nil {
				if err2 := os.Rename(tmp, dst); err2 == nil {
					_ = os.Remove(dst + ".old")
					return nil
				}
			}
		}
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
