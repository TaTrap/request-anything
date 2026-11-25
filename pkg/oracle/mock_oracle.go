package oracle

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TaTrap/request-anything/pkg/models"
)

type mockSessionState struct {
	Config           SessionConfig   `json:"config"`
	ReportCounter    int             `json:"report_counter"`
	SignCounter      int             `json:"sign_counter"`
	InFlightReqIDs   map[string]bool `json:"in_flight_req_ids"`
	Pending          []AsyncPacket   `json:"pending"`
	WorkerExceptions int             `json:"worker_exceptions"`
	LastError        string          `json:"last_error"`
	DeliveredReqIDs  []string        `json:"delivered_req_ids"`
	RandomSalt       uint32          `json:"random_salt"`
}

// MockOracle implements NativeOracle in-process for testing portable snapshots,
// reqID-correlated response delivery, async telemetry packets, and oracle_verify claims.
type MockOracle struct {
	mu               sync.Mutex
	sessions         map[SessionHandle]*mockSessionState
	nextID           atomic.Uint64
	SimulateRandomIV bool
}

// NewMockOracle constructs a stateful in-memory mock NativeOracle.
func NewMockOracle() *MockOracle {
	return &MockOracle{
		sessions: make(map[SessionHandle]*mockSessionState),
	}
}

func (m *MockOracle) Open(_ context.Context, cfg SessionConfig) (SessionHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID.Add(1)
	h := SessionHandle(fmt.Sprintf("mock-sess-%d", id))
	m.sessions[h] = &mockSessionState{
		Config:         cfg,
		InFlightReqIDs: make(map[string]bool),
		RandomSalt:     cfg.PinnedSeed + uint32(id),
	}
	return h, nil
}

func (m *MockOracle) Snapshot(_ context.Context, h SessionHandle) (*NativeSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return nil, fmt.Errorf("unknown handle %s", h)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return &NativeSnapshot{
		SnapshotID:    fmt.Sprintf("snap-%s-%d", h, st.SignCounter),
		SchemaVersion: "mock-oracle/v1",
		AppVersion:    st.Config.AppVersion,
		DeviceID:      st.Config.DeviceID,
		InstallID:     st.Config.InstallID,
		Payload:       payload,
	}, nil
}

func (m *MockOracle) Restore(_ context.Context, h SessionHandle, snap *NativeSnapshot) error {
	if snap == nil || len(snap.Payload) == 0 {
		return fmt.Errorf("cannot restore empty snapshot payload")
	}
	var restored mockSessionState
	if err := json.Unmarshal(snap.Payload, &restored); err != nil {
		return fmt.Errorf("corrupt snapshot payload: %w", err)
	}
	if restored.InFlightReqIDs == nil {
		restored.InFlightReqIDs = make(map[string]bool)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[h]; !ok {
		return fmt.Errorf("unknown handle %s", h)
	}
	m.sessions[h] = &restored
	return nil
}

func (m *MockOracle) Close(_ context.Context, h SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, h)
	return nil
}

// InjectException simulates an unhandled native JNI/unidbg exception inside the session.
func (m *MockOracle) InjectException(h SessionHandle, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.sessions[h]; ok {
		st.WorkerExceptions++
		st.LastError = msg
	}
}

// UpdateDevice updates DID/IID inside native session after device_register succeeds.
func (m *MockOracle) UpdateDevice(h SessionHandle, did, iid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return fmt.Errorf("unknown handle %s", h)
	}
	st.Config.DeviceID = did
	st.Config.InstallID = iid
	return nil
}

func (m *MockOracle) Sign(_ context.Context, h SessionHandle, reqID string, in SignInput) (*SignOutput, error) {
	if reqID == "" {
		return nil, fmt.Errorf("Sign requires non-empty reqID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return nil, fmt.Errorf("unknown handle %s", h)
	}
	st.SignCounter++
	st.InFlightReqIDs[reqID] = true

	ts := in.NowMs / 1000
	if ts == 0 {
		ts = st.Config.NowMs / 1000
	}
	if ts == 0 {
		ts = 1700000000
	}
	sum := md5.Sum(in.Body)
	bodyMD5 := strings.ToUpper(hex.EncodeToString(sum[:]))

	iv := "fixed-iv"
	if m.SimulateRandomIV {
		st.RandomSalt += 17
		iv = fmt.Sprintf("rnd-%d-%d", st.SignCounter, st.RandomSalt)
	}

	// Structured mock claims payload that oracle_verify decodes and validates
	claims := map[string]any{
		"app_id":   extractQueryParam(in.RawQuery, "app_id"),
		"did":      st.Config.DeviceID,
		"iid":      st.Config.InstallID,
		"ts":       fmt.Sprintf("%d", ts),
		"body_md5": bodyMD5,
		"counter":  st.SignCounter,
		"iv":       iv,
	}
	claimsJSON, _ := json.Marshal(claims)
	claimsToken := base64.StdEncoding.EncodeToString(claimsJSON)
	reqSig := fmt.Sprintf("sig1%04x%s", st.SignCounter, strings.ToLower(bodyMD5[:8]))

	out := &SignOutput{
		Headers: map[string]string{
			"content-md5": bodyMD5,
			"x-timestamp": fmt.Sprintf("%d", ts),
			"x-signature": reqSig,
			"signature":   claimsToken,
		},
	}

	// Emit async /telemetry/report packet on first register sign
	if st.ReportCounter == 0 && strings.Contains(in.URL, "register") {
		st.ReportCounter++
		pkt := AsyncPacket{
			PacketID:  fmt.Sprintf("pkt-%d", st.ReportCounter),
			Endpoint:  "/telemetry/report",
			Method:    "POST",
			Body:      []byte(fmt.Sprintf("telemetry_report_cnt=%d", st.ReportCounter)),
			Triggered: reqID,
		}
		st.Pending = append(st.Pending, pkt)
		out.Queued = []AsyncPacket{pkt}
	}
	return out, nil
}

func (m *MockOracle) PendingPackets(_ context.Context, h SessionHandle) ([]AsyncPacket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return nil, fmt.Errorf("unknown handle %s", h)
	}
	out := append([]AsyncPacket(nil), st.Pending...)
	st.Pending = nil
	return out, nil
}

func (m *MockOracle) DeliverResponse(_ context.Context, h SessionHandle, reqID string, resp *models.WireResponse) (*DeliverResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return nil, fmt.Errorf("unknown handle %s", h)
	}
	if !st.InFlightReqIDs[reqID] {
		return nil, fmt.Errorf("response correlation error: unknown or already-delivered reqID %q (FIFO delivery forbidden)", reqID)
	}
	delete(st.InFlightReqIDs, reqID)
	st.DeliveredReqIDs = append(st.DeliveredReqIDs, reqID)

	var followUps []AsyncPacket
	if resp != nil && resp.Status == 200 && strings.Contains(string(resp.Body.RawBytes), "trigger_telemetry") {
		st.ReportCounter++
		followUps = append(followUps, AsyncPacket{
			PacketID:  fmt.Sprintf("pkt-%d", st.ReportCounter),
			Endpoint:  "/telemetry/report",
			Method:    "POST",
			Body:      []byte(fmt.Sprintf("telemetry_followup=%d", st.ReportCounter)),
			Triggered: reqID,
		})
	}
	return &DeliverResult{
		Packets: followUps,
		Health: &OracleHealth{
			Healthy:          st.WorkerExceptions == 0,
			WorkerExceptions: st.WorkerExceptions,
			LastError:        st.LastError,
			ActiveHandles:    len(m.sessions),
		},
		Completed: true,
	}, nil
}

func (m *MockOracle) Health(_ context.Context, h SessionHandle) (*OracleHealth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[h]
	if !ok {
		return nil, fmt.Errorf("unknown handle %s", h)
	}
	return &OracleHealth{
		Healthy:          st.WorkerExceptions == 0,
		WorkerExceptions: st.WorkerExceptions,
		LastError:        st.LastError,
		ActiveHandles:    len(m.sessions),
	}, nil
}

func extractQueryParam(rawQuery, key string) string {
	for _, seg := range strings.Split(strings.TrimSuffix(rawQuery, "&"), "&") {
		if k, v, ok := strings.Cut(seg, "="); ok && k == key {
			return v
		}
	}
	return ""
}
