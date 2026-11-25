package pin

import "testing"

func TestMulberry32DeterministicSequence(t *testing.T) {
	// Reference vector for seed=7 computed with identical wrapping u32 arithmetic.
	seq1 := Sequence(7, 3)
	seq2 := Sequence(7, 3)
	for i := range seq1 {
		if seq1[i] != seq2[i] {
			t.Fatalf("non-deterministic at %d: %d vs %d", i, seq1[i], seq2[i])
		}
	}
	if seq1[0] == seq1[1] {
		t.Fatalf("expected distinct consecutive outputs")
	}
	// Verify exact bit arithmetic for seed=7, step 1
	s := uint32(7) + 0x6D2B79F5
	x := (s ^ (s >> 15)) * (s | 1)
	x ^= x + ((x ^ (x >> 7)) * (x | 61))
	want0 := x ^ (x >> 14)
	if seq1[0] != want0 {
		t.Fatalf("mulberry32 mismatch: want %d, got %d", want0, seq1[0])
	}
}
