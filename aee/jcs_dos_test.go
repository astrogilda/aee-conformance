package aee

import (
	"errors"
	"strings"
	"testing"
)

// TestParseDepthBound proves the JCS parser rejects deeply nested untrusted
// input with a normal, catchable error instead of recursing to an uncatchable
// stack overflow (the DoS this bound closes).
func TestParseDepthBound(t *testing.T) {
	tooDeep := strings.Repeat("[", maxParseDepth*2) + strings.Repeat("]", maxParseDepth*2)
	if _, err := Canonicalize([]byte(tooDeep)); !errors.Is(err, ErrInputTooDeep) {
		t.Fatalf("Canonicalize(tooDeep): want ErrInputTooDeep, got %v", err)
	}
	if err := CheckIJSON([]byte(tooDeep)); !errors.Is(err, ErrInputTooDeep) {
		t.Fatalf("CheckIJSON(tooDeep): want ErrInputTooDeep, got %v", err)
	}
	// A payload at the bound still canonicalizes (the guard is not over-tight).
	atBound := strings.Repeat("[", maxParseDepth) + strings.Repeat("]", maxParseDepth)
	if _, err := Canonicalize([]byte(atBound)); err != nil {
		t.Fatalf("Canonicalize(depth=%d): want ok, got %v", maxParseDepth, err)
	}
}

// TestParseByteBound proves oversized untrusted input is rejected before
// parsing, so the depth cap (stack) is paired with a size cap (heap).
func TestParseByteBound(t *testing.T) {
	big := make([]byte, maxParseBytes+1)
	for i := range big {
		big[i] = ' '
	}
	big[0], big[len(big)-1] = '[', ']'
	if _, err := Canonicalize(big); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("Canonicalize(oversized): want ErrInputTooLarge, got %v", err)
	}
}
