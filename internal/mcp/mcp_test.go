package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestMCPConcurrencyCancellationPromptsAndFailures(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize + tools/list annotations + prompts/get
	initResp := HandleMessage(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": ProtocolVersion},
	})
	if initResp["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "request-anything" {
		t.Fatalf("unexpected serverInfo: %+v", initResp)
	}
	listResp := HandleMessage(ctx, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	tools := listResp["result"].(map[string]any)["tools"].([]map[string]any)
	if len(tools) != len(toolMetas) {
		t.Fatalf("expected %d tools, got %d", len(toolMetas), len(tools))
	}
	pResp := HandleMessage(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "prompts/get",
		"params": map[string]any{"name": "port_request", "arguments": map[string]any{"unit": "/repo/unit"}},
	})
	pText := pResp["result"].(map[string]any)["messages"].([]map[string]any)[0]["content"].(map[string]any)["text"].(string)
	if !strings.Contains(pText, "/repo/unit") || strings.HasPrefix(pText, "---") {
		t.Fatalf("bad prompt rendering: %q", pText)
	}

	// 2. Structured FAILURES test
	bad := HandleMessage(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]any{"name": "gate", "arguments": map[string]any{}},
	})
	res := bad["result"].(map[string]any)
	if res["isError"] != true || res["structuredContent"].(map[string]any)["code"] != "invalid_arguments" {
		t.Fatalf("unexpected structured error: %+v", res)
	}

	// 3. Concurrency + Ping beats slow call + notifications/cancelled suppresses reply
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_sleep","arguments":{"ms":250},"_meta":{"progressToken":"p1"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_sleep","arguments":{"ms":4000}}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	}, "\n") + "\n"

	var out syncBuffer
	if err := ServeIO(ctx, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var msgs []map[string]any
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("invalid json line %q: %v", l, err)
		}
		msgs = append(msgs, m)
	}

	posOf := func(id float64) int {
		for i, m := range msgs {
			if mid, ok := m["id"].(float64); ok && mid == id {
				return i
			}
		}
		return -1
	}
	p3 := posOf(3)
	p1 := posOf(1)
	p2 := posOf(2)
	if p3 < 0 || p1 < 0 || p3 > p1 {
		t.Fatalf("expected ping(3) before slow call(1): p3=%d p1=%d\n%s", p3, p1, out.String())
	}
	if p2 != -1 {
		t.Fatalf("cancelled request(2) must produce no reply, got index %d", p2)
	}
}
