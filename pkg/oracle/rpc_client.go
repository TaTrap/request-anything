package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TaTrap/request-anything/pkg/models"
)

// RPCClient connects to an external unidbg / Frida HTTP JSON-RPC sidecar implementing NativeOracle.
type RPCClient struct {
	Endpoint string
	HTTP     *http.Client
}

// NewRPCClient creates an HTTP JSON sidecar oracle client.
func NewRPCClient(endpoint string) *RPCClient {
	return &RPCClient{
		Endpoint: strings.TrimRight(endpoint, "/"),
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (r *RPCClient) call(ctx context.Context, path string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := r.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	if httpResp.StatusCode >= 300 {
		return fmt.Errorf("oracle RPC %s returned %d: %s", path, httpResp.StatusCode, string(raw))
	}
	if resp != nil && len(raw) > 0 {
		return json.Unmarshal(raw, resp)
	}
	return nil
}

func (r *RPCClient) Open(ctx context.Context, cfg SessionConfig) (SessionHandle, error) {
	var out struct {
		Handle SessionHandle `json:"handle"`
	}
	err := r.call(ctx, "/open", cfg, &out)
	return out.Handle, err
}

func (r *RPCClient) Snapshot(ctx context.Context, h SessionHandle) (*NativeSnapshot, error) {
	var out NativeSnapshot
	err := r.call(ctx, "/snapshot", map[string]any{"handle": h}, &out)
	return &out, err
}

func (r *RPCClient) Restore(ctx context.Context, h SessionHandle, snap *NativeSnapshot) error {
	return r.call(ctx, "/restore", map[string]any{"handle": h, "snapshot": snap}, nil)
}

func (r *RPCClient) Close(ctx context.Context, h SessionHandle) error {
	return r.call(ctx, "/close", map[string]any{"handle": h}, nil)
}

func (r *RPCClient) Sign(ctx context.Context, h SessionHandle, reqID string, in SignInput) (*SignOutput, error) {
	var out SignOutput
	err := r.call(ctx, "/sign", map[string]any{"handle": h, "req_id": reqID, "input": in}, &out)
	return &out, err
}

func (r *RPCClient) PendingPackets(ctx context.Context, h SessionHandle) ([]AsyncPacket, error) {
	var out struct {
		Packets []AsyncPacket `json:"packets"`
	}
	err := r.call(ctx, "/pending_packets", map[string]any{"handle": h}, &out)
	return out.Packets, err
}

func (r *RPCClient) DeliverResponse(ctx context.Context, h SessionHandle, reqID string, resp *models.WireResponse) (*DeliverResult, error) {
	var out DeliverResult
	err := r.call(ctx, "/deliver_response", map[string]any{"handle": h, "req_id": reqID, "response": resp}, &out)
	return &out, err
}

func (r *RPCClient) Health(ctx context.Context, h SessionHandle) (*OracleHealth, error) {
	var out OracleHealth
	err := r.call(ctx, "/health", map[string]any{"handle": h}, &out)
	return &out, err
}
