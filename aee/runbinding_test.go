package aee

import "testing"

// TestDeriveBindingFailsClosedOnMalformedInput proves the run-binding
// derivation does not panic when reached (via the exported DeriveTiers /
// CheckRecordSignatures entry points) on a statement a library consumer has
// not gated: an empty subject or an absent environment yields a derived
// binding built from empty inputs instead of an index-out-of-range panic.
func TestDeriveBindingFailsClosedOnMalformedInput(t *testing.T) {
	cases := []*Statement{
		{Predicate: &Predicate{Env: &Environment{}}}, // nil subject, present env
		{Predicate: &Predicate{}},                    // nil subject, nil env
	}
	for i, s := range cases {
		got := deriveStatementBinding(s) // must not panic
		if len(got) != 64 {
			t.Fatalf("case %d: want a 64-hex fail-closed binding, got %q", i, got)
		}
	}
}
