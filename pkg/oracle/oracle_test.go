package oracle

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/TaTrap/request-anything/pkg/models"
)

func TestMockOraclePortableSnapshotLaneAndCorrelation(t *testing.T) {
	ctx := context.Background()
	raw1 := NewMockOracle()
	raw1.SimulateRandomIV = true
	o1 := NewSerializedOracle(raw1)

	h, err := o1.Open(ctx, SessionConfig{
		AppVersion: "35.0.0",
		DeviceID:   "7300112233",
		InstallID:  "7300445566",
		PinnedSeed: 42,
		NowMs:      1700000000000,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Parallel bursts serialized cleanly through per-handle mutex lane
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqID := string(rune('a' + idx))
			_, sErr := o1.Sign(ctx, h, "req-"+reqID, SignInput{
				Method:   "POST",
				URL:      "https://api.example.com/v1/device/register",
				RawQuery: "app_id=1001",
				Body:     []byte(`{"k":1}`),
			})
			if sErr != nil {
				t.Errorf("concurrent sign failed: %v", sErr)
			}
		}(i)
	}
	wg.Wait()

	// Portable snapshot serialized to JSON bytes -> restored on a fresh oracle instance (simulating JVM restart)
	snap, err := o1.Snapshot(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	snapBytes, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var diskSnap NativeSnapshot
	if err := json.Unmarshal(snapBytes, &diskSnap); err != nil {
		t.Fatal(err)
	}

	raw2 := NewMockOracle()
	o2 := NewSerializedOracle(raw2)
	h2, err := o2.Open(ctx, SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := o2.Restore(ctx, h2, &diskSnap); err != nil {
		t.Fatal(err)
	}

	// Wrong reqID delivery must fail (anti-FIFO)
	if _, err := o2.DeliverResponse(ctx, h2, "wrong-req-id", &models.WireResponse{Status: 200}); err == nil {
		t.Fatalf("expected error on mismatched reqID delivery")
	}

	// Valid reqID delivers and emits follow-up telemetry packet
	res, err := o2.DeliverResponse(ctx, h2, "req-a", &models.WireResponse{
		Status: 200,
		Body:   models.WireBody{RawBytes: []byte(`{"trigger_telemetry":true}`)},
	})
	if err != nil {
		t.Fatalf("valid DeliverResponse failed: %v", err)
	}
	if len(res.Packets) != 1 || res.Packets[0].Endpoint != "/telemetry/report" {
		t.Fatalf("expected /telemetry/report follow-up packet, got %+v", res.Packets)
	}

	// Verify Signature claims bindings via oracle_verify
	sigOut, err := o2.Sign(ctx, h2, "req-verify", SignInput{
		Method:   "POST",
		URL:      "https://api.example.com/v2/feed/",
		RawQuery: "app_id=1001",
		Body:     []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := VerifySignatureRule(ctx, models.FieldRule{
		Target:     "header.signature",
		Mode:       "signed",
		SignerMode: "oracle_verify",
		OracleHook: "builtin:claims-json",
		Claims: map[string]string{
			"app_id":   "@query.app_id",
			"did":      "7300112233",
			"body_md5": "@body_md5",
		},
	}, "ignored-old-token", sigOut.Headers["signature"], &models.WireRequest{
		RawQuery: "app_id=1001",
		Body:     models.WireBody{RawBytes: []byte(`{"ok":true}`)},
	})
	if finding != nil {
		t.Fatalf("expected oracle_verify to pass, got %+v", finding)
	}
	if !strings.HasPrefix(sigOut.Headers["x-signature"], "sig1") {
		t.Fatalf("unexpected x-signature: %s", sigOut.Headers["x-signature"])
	}

	// Verify cross-platform external cmd: verifier runs cleanly on Windows & POSIX
	extFinding := VerifySignatureRule(ctx, models.FieldRule{
		Target:     "header.x-custom-sig",
		Mode:       "signed",
		SignerMode: "oracle_verify",
		OracleHook: "cmd:echo ok",
	}, "", "nonempty", nil)
	if extFinding != nil {
		t.Fatalf("expected cross-platform external verifier to pass, got %+v", extFinding)
	}
}
