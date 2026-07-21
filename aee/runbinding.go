package aee

import "fmt"

// BindingVersion is the only run-binding construction this implementation
// derives. A future version that changes the construction names a new
// binding version; a verifier MUST reject, fail-closed, a binding version
// it does not implement rather than attempt more than one construction
// (spec:98-103). There is deliberately exactly ONE construction here.
const BindingVersion = "1"

// RunBindingPreimage builds the RFC 8785 canonical bytes of the binding
// pre-image object (spec:72-78):
//
//	{"aeeBindingVersion":"1","catchPolicy":"<hex>","corpus":"<hex>",
//	 "networkPosture":"<hex>","runEntropy":"<hex>","subject":"<hex>",
//	 "substrate":"<hex>"}
//
// The member names are emitted in their JCS (UTF-16 code unit) order, which
// for these seven ASCII names is the literal order below. Values are taken
// verbatim (no case-folding, no null fill, spec:85-86); a value that is not
// lowercase 64-hex has already been rejected at GATE 0 for any statement
// that reaches a binding derivation. Hex strings never require JSON string
// escaping, so direct formatting below emits exactly the JCS bytes.
func RunBindingPreimage(catchPolicy, corpus, networkPosture, runEntropy, subject, substrate string) []byte {
	return []byte(fmt.Sprintf(
		`{"aeeBindingVersion":%q,"catchPolicy":%q,"corpus":%q,"networkPosture":%q,"runEntropy":%q,"subject":%q,"substrate":%q}`,
		BindingVersion, catchPolicy, corpus, networkPosture, runEntropy, subject, substrate))
}

// DeriveRunBinding returns the lowercase 64-hex SHA-256 of the binding
// pre-image. A verifier derives this from the statement alone; no field
// carries it (spec:87-88).
func DeriveRunBinding(catchPolicy, corpus, networkPosture, runEntropy, subject, substrate string) string {
	return SHA256Hex(RunBindingPreimage(catchPolicy, corpus, networkPosture, runEntropy, subject, substrate))
}

// deriveStatementBinding derives the run binding for a substrate-carrying
// statement whose GATE 0 checks have passed (all six inputs present and
// lowercase 64-hex).
// The exported GATE 2 / producer-QA entry points (DeriveTiers,
// CheckRecordSignatures) are reachable from a library consumer that may pass a
// statement which has NOT passed GATE 0 (empty subject, absent environment).
// Fail closed rather than panic: a missing subject or environment yields a
// binding built from empty inputs, which matches no real record's binding, so
// substrate rows fall to unattested and the QA check reports a mismatch.
func deriveStatementBinding(s *Statement) string {
	env := s.Predicate.Env
	if env == nil {
		return DeriveRunBinding("", "", "", "", "", "")
	}
	subjectHash := ""
	if len(s.Subject) > 0 {
		subjectHash = s.Subject[0].Digest["sha256"]
	}
	return DeriveRunBinding(
		env.CatchPolicy.Sha256(),
		env.Corpus.Sha256(),
		env.NetworkPosture.Sha256(),
		env.RunEntropy.Sha256(),
		subjectHash,
		env.Substrate.Sha256(),
	)
}
