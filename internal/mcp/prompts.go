package mcp

import (
	"fmt"
	"strings"

	"github.com/TaTrap/request-anything/skills"
)

// ListPrompts returns MCP prompts/list payload.
func ListPrompts() map[string]any {
	return map[string]any{
		"prompts": []map[string]any{
			{
				"name":        "port_request",
				"title":       "Port an API request to Go",
				"description": "Import capture, scaffold Go port, verify 6-layer diff and positive gate assertions.",
				"arguments": []map[string]any{
					{"name": "unit", "description": "Target unit folder.", "required": true},
				},
			},
			{
				"name":        "port_flow",
				"title":       "Port a stateful multi-step API flow to Go",
				"description": "Run scenario matrix, per-step portable snapshots, parallel bursts, and flow lift.",
				"arguments": []map[string]any{
					{"name": "flow_dir", "description": "Target flow directory.", "required": true},
				},
			},
		},
	}
}

// GetPrompt resolves MCP prompts/get for port_request and port_flow.
func GetPrompt(name string, args map[string]any) (map[string]any, error) {
	unit, _ := args["unit"].(string)
	flowDir, _ := args["flow_dir"].(string)
	switch name {
	case "port_request":
		if strings.TrimSpace(unit) == "" {
			return nil, fmt.Errorf("prompt `port_request` needs the `unit` argument")
		}
		text := fmt.Sprintf("Port the API request unit at %s to Go using request-anything. Done means gate passes.\n\n%s",
			unit, stripFrontmatter(skills.SkillMD))
		return map[string]any{
			"description": "Port an API request to Go",
			"messages": []map[string]any{
				{"role": "user", "content": map[string]any{"type": "text", "text": text}},
			},
		}, nil
	case "port_flow":
		if strings.TrimSpace(flowDir) == "" {
			return nil, fmt.Errorf("prompt `port_flow` needs the `flow_dir` argument")
		}
		text := fmt.Sprintf("Port the multi-step API flow at %s to Go using request-anything.\n\n%s\n\n%s",
			flowDir, stripFrontmatter(skills.WholeFlowMD), stripFrontmatter(skills.SkillMD))
		return map[string]any{
			"description": "Port a stateful multi-step API flow to Go",
			"messages": []map[string]any{
				{"role": "user", "content": map[string]any{"type": "text", "text": text}},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown prompt `%s`", name)
	}
}

func stripFrontmatter(md string) string {
	s := strings.TrimPrefix(md, "---\r\n")
	s = strings.TrimPrefix(s, "---\n")
	if idx := strings.Index(s, "\n---"); idx >= 0 {
		rest := s[idx+4:]
		rest = strings.TrimLeft(rest, "\r\n")
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(md)
}
