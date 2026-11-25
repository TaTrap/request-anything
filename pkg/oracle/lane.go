package oracle

import (
	"context"
	"sync"

	"github.com/TaTrap/request-anything/pkg/models"
)

// SerializedOracle wraps any NativeOracle and enforces a per-SessionHandle mutex/lane.
// HTTP network calls inside a parallel_group execute concurrently, while all native calls on the
// same SessionHandle serialize strictly to prevent counter & snapshot races.
type SerializedOracle struct {
	inner NativeOracle
	mu    sync.Mutex
	lanes map[SessionHandle]*sync.Mutex
}

// NewSerializedOracle wraps inner with per-SessionHandle lane serialization.
func NewSerializedOracle(inner NativeOracle) *SerializedOracle {
	return &SerializedOracle{
		inner: inner,
		lanes: make(map[SessionHandle]*sync.Mutex),
	}
}

func (s *SerializedOracle) laneFor(h SessionHandle) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.lanes[h]
	if !ok {
		l = &sync.Mutex{}
		s.lanes[h] = l
	}
	return l
}

func (s *SerializedOracle) Open(ctx context.Context, cfg SessionConfig) (SessionHandle, error) {
	h, err := s.inner.Open(ctx, cfg)
	if err == nil {
		_ = s.laneFor(h)
	}
	return h, err
}

func (s *SerializedOracle) Snapshot(ctx context.Context, h SessionHandle) (*NativeSnapshot, error) {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.Snapshot(ctx, h)
}

func (s *SerializedOracle) Restore(ctx context.Context, h SessionHandle, snap *NativeSnapshot) error {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.Restore(ctx, h, snap)
}

func (s *SerializedOracle) Close(ctx context.Context, h SessionHandle) error {
	l := s.laneFor(h)
	l.Lock()
	err := s.inner.Close(ctx, h)
	l.Unlock()
	s.mu.Lock()
	delete(s.lanes, h)
	s.mu.Unlock()
	return err
}

func (s *SerializedOracle) Sign(ctx context.Context, h SessionHandle, reqID string, in SignInput) (*SignOutput, error) {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.Sign(ctx, h, reqID, in)
}

func (s *SerializedOracle) PendingPackets(ctx context.Context, h SessionHandle) ([]AsyncPacket, error) {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.PendingPackets(ctx, h)
}

func (s *SerializedOracle) DeliverResponse(ctx context.Context, h SessionHandle, reqID string, resp *models.WireResponse) (*DeliverResult, error) {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.DeliverResponse(ctx, h, reqID, resp)
}

func (s *SerializedOracle) Health(ctx context.Context, h SessionHandle) (*OracleHealth, error) {
	l := s.laneFor(h)
	l.Lock()
	defer l.Unlock()
	return s.inner.Health(ctx, h)
}
