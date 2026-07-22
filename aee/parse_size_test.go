package aee

import (
	"errors"
	"testing"
)

// TestParseStatementSizeCap proves an oversized statement is rejected before it
// is unmarshaled, bounding memory on untrusted input (the per-payload and depth
// caps do not bound the outer statement).
func TestParseStatementSizeCap(t *testing.T) {
	big := make([]byte, maxStatementBytes+1)
	if _, err := ParseStatement(big); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("oversized statement: want ErrInputTooLarge, got %v", err)
	}
	// A small statement is not rejected on size grounds (it fails to parse as
	// JSON instead, which is a different error).
	if _, err := ParseStatement([]byte("{}")); errors.Is(err, ErrInputTooLarge) {
		t.Fatal("a tiny statement was wrongly rejected as too large")
	}
}
