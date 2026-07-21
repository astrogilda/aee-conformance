package aee

import (
	"fmt"
	"strings"
)

// Report is the outcome of a full verification run.
//
// Behavior contract (mirrors the conformance suite's behavior assertions):
// an invalid report carries NO Result and NO Tiers — a consumer must never
// see a result it is forbidden to consume (spec:257-261).
type Report struct {
	// Verdict is "valid" or "invalid".
	Verdict string `json:"verdict"`
	// Codes lists every detected failure code in pinned detection order;
	// empty when valid.
	Codes []Code `json:"codes,omitempty"`
	// PrimaryCode is Codes[0] — the deterministic primary code ("" when
	// valid). Conformance compares the primary code for set membership;
	// code ORDER beyond the primary is never part of the contract.
	PrimaryCode Code `json:"primaryCode,omitempty"`
	// Result is the carried (and recompute-confirmed) result; only set when
	// valid.
	Result string `json:"result,omitempty"`
	// Tiers is the derived per-row evidence tier column, in attackResults
	// order; only set when valid.
	Tiers []Tier `json:"tiers,omitempty"`
}

const (
	VerdictValid   = "valid"
	VerdictInvalid = "invalid"
)

// Verify runs the full consumer pipeline over one in-toto statement:
//
//	GATE 0 (statement well-formedness)
//	GATE 1 (coverage validity — consumption precondition)
//	recompute equality (carried result == pure recompute)
//	GATE 2 (evidence tier, per the given key policy)
//
// The gates run in that order and the pipeline stops at the first failing
// gate: a statement that fails GATE 0 is invalid regardless of anything a
// later gate might have said, and neither Result nor Tiers is ever derived
// for an invalid statement.
func Verify(statementJSON []byte, policy *KeyPolicy) *Report {
	s, err := ParseStatement(statementJSON)
	if err != nil {
		return &Report{Verdict: VerdictInvalid, Codes: []Code{CodeStatementMalformed}, PrimaryCode: CodeStatementMalformed}
	}
	if codes := Gate0(s); len(codes) > 0 {
		return invalidReport(codes)
	}
	if codes := Gate1(s); len(codes) > 0 {
		return invalidReport(codes)
	}
	if got := Recompute(s.Predicate); got != s.Predicate.Result {
		return invalidReport([]Code{CodeResultRecomputeMismatch})
	}
	return &Report{
		Verdict: VerdictValid,
		Result:  s.Predicate.Result,
		Tiers:   DeriveTiers(s, policy),
	}
}

// VerifyForEmit is the producer-side seam: GATE 0 + GATE 1 + recompute
// equality, with no tier (the tier is trust-relative and consumer-derived
// by definition; it never runs at emit). A non-nil error means the
// statement MUST NOT be signed.
func VerifyForEmit(statementJSON []byte) error {
	s, err := ParseStatement(statementJSON)
	if err != nil {
		return fmt.Errorf("statement does not parse: %w", err)
	}
	if codes := Gate0(s); len(codes) > 0 {
		return fmt.Errorf("statement fails GATE 0 (well-formedness): %s", joinCodes(codes))
	}
	if codes := Gate1(s); len(codes) > 0 {
		return fmt.Errorf("statement fails GATE 1 (coverage validity): %s", joinCodes(codes))
	}
	if got := Recompute(s.Predicate); got != s.Predicate.Result {
		return fmt.Errorf("carried result %q != recomputed %q (%s)", s.Predicate.Result, got, CodeResultRecomputeMismatch)
	}
	return nil
}

func invalidReport(codes []Code) *Report {
	return &Report{Verdict: VerdictInvalid, Codes: codes, PrimaryCode: codes[0]}
}

func joinCodes(codes []Code) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}
