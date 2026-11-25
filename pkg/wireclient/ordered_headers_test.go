package wireclient

import (
	"testing"

	"github.com/TaTrap/request-anything/pkg/models"
)

func TestOrderedHeadersSetPreservesOriginalCasing(t *testing.T) {
	h := NewOrderedHeaders([]models.HeaderKV{
		{RawName: "Signature", Value: "old-token"},
		{RawName: "X-Signature", Value: "old-sig"},
	})
	h.Set("signature", "new-token")
	h.Set("X-Custom-New", "v1")

	if h.Items[0].RawName != "Signature" || h.Items[0].Value != "new-token" {
		t.Fatalf("expected original casing Signature preserved, got %+v", h.Items[0])
	}
	if h.Items[2].RawName != "X-Custom-New" || h.Items[2].Value != "v1" {
		t.Fatalf("expected appended header X-Custom-New, got %+v", h.Items[2])
	}

	h.SetWithCasing("x-signature", "new-sig")
	if h.Items[1].RawName != "x-signature" || h.Items[1].Value != "new-sig" {
		t.Fatalf("expected SetWithCasing to update casing, got %+v", h.Items[1])
	}
}
