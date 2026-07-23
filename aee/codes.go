// Package aee implements the verification core for the in-toto
// Adversarial Execution Evidence predicate, version 0.6
// (predicateType https://in-toto.io/attestation/adversarial-execution-evidence/v0.6).
//
// The category of attestation this predicate defines is a recomputable
// execution attestation: the consumer recomputes the outcome from carried
// bytes (execute-and-attest), rather than matching a producer-asserted
// verdict (match-and-assert).
//
// The verification pipeline is a strict two-gate design plus a recompute
// equality check and a trust-relative tier:
//
//	GATE 0  statement well-formedness   (statement.go) — spec "Parsing Rules" + field shapes
//	GATE 1  coverage validity           (validity.go)  — spec "Coverage validity"; a
//	        consumption precondition: on failure the attestation is INVALID and its
//	        result MUST NOT be consumed
//	        recompute equality          (recompute.go) — carried result must equal the
//	        pure recompute over carried bytes
//	GATE 2  evidence tier               (tier.go)      — {declared|unattested|attested},
//	        trust-relative, derived per consumer key policy; never alters result
//
// Spec line references in this package are to the predicate specification at
// commit 4a36b19 (spec/predicates/adversarial-execution-evidence.md).
package aee

// Code is a stable, machine-readable failure code. The registry of codes and
// their precedence pins is documented in the conformance suite README; the
// codes here are the implementation's closed set. Message text is never part
// of the conformance contract; codes are.
type Code string

// GATE 0 — statement well-formedness codes.
const (
	CodeStatementMalformed        Code = "statement-malformed" // catch-all: unparseable JSON / wrong member type
	CodeStatementTypeUnsupported  Code = "statement-type-unsupported"
	CodePredicateTypeUnsupported  Code = "predicate-type-unsupported"
	CodeMemberSpelling            Code = "member-spelling"
	CodeResultVocabulary          Code = "result-vocabulary"
	CodeEnvironmentIncomplete     Code = "environment-incomplete"
	CodeVocabularyMissing         Code = "vocabulary-missing"
	CodeVocabularyNotCanonical    Code = "vocabulary-not-canonical"
	CodeVocabularyCaughtNotSubset Code = "vocabulary-caught-not-subset"
	CodeVocabularyDigestMismatch  Code = "vocabulary-digest-mismatch"
	CodeCorpusDigestMismatch      Code = "corpus-digest-mismatch"
	CodeManifestDuplicateAttack   Code = "manifest-duplicate-attack"
	CodeCoverageMissing           Code = "coverage-missing"
	CodeCoverageIncomplete        Code = "coverage-incomplete"
	CodeRowAttackUnknown          Code = "row-attack-unknown"
	CodeMissingActualLayer        Code = "malformed-missing-actual-layer"
	CodeCleanRowLayerNotNone      Code = "clean-row-layer-not-none"
	CodeSubjectCardinality        Code = "subject-cardinality"
	CodeSubjectSha256Missing      Code = "subject-sha256-missing"
	CodeDigestNotCanonical        Code = "digest-not-canonical"
	CodeRunEntropyMissing         Code = "run-entropy-missing"
	CodeIssuedAtMissing           Code = "issued-at-missing"
	CodeIssuedAtMalformed         Code = "issued-at-malformed"
)

// GATE 1 — statement-level observation-record codes (evaluated whenever
// observationRecords is non-empty, BEFORE any per-row logic).
const (
	CodeBatchRootMissing  Code = "batch-root-missing"
	CodeBatchRootMismatch Code = "batch-root-mismatch"
	CodeBatchRootOrphaned Code = "batch-root-orphaned"
	CodeDuplicateRecord   Code = "duplicate-record"
	CodeRecordsAbsent     Code = "records-absent"
	CodeRecordUndecodable Code = "record-undecodable" // registry extension: a record whose payload is not valid base64 (no committed vector; documented)
)

// GATE 1 — per-row coverage-validity codes.
const (
	CodeRefsEmpty                      Code = "refs-empty"
	CodeRefMalformed                   Code = "ref-malformed"
	CodeRefOutOfRange                  Code = "ref-out-of-range"
	CodeFailClosedSubstrateRow         Code = "fail-closed-substrate-row"
	CodePayloadNotIJSON                Code = "payload-not-ijson"
	CodePayloadNotCanonical            Code = "payload-not-canonical"
	CodePayloadMediaType               Code = "payload-media-type"
	CodePayloadMissingReserved         Code = "payload-missing-reserved"
	CodeRunBindingMismatch             Code = "run-binding-mismatch"
	CodeMethodCapExceeded              Code = "method-cap-exceeded"
	CodeCaughtRowUncovered             Code = "caught-row-uncovered"
	CodeReconstructedRowUncovered      Code = "reconstructed-row-uncovered"
	CodeCleanRowUncovered              Code = "clean-row-uncovered"
	CodeArmingCoversNothing            Code = "arming-covers-nothing"
	CodeSealedCoversNothing            Code = "sealed-covers-nothing"
	CodeExaminationCoversNothing       Code = "examination-covers-nothing"
	CodeRecordKindUnknownCoversNothing Code = "record-kind-unknown-covers-nothing"
)

// Recompute-equality gate.
const (
	CodeResultRecomputeMismatch Code = "result-recompute-mismatch"
)

// Consumer-policy stage codes. These are consumer-relative admission facts,
// recorded on the report's consumer surface (Report.PolicyCodes) and folded
// into Admitted; they are NEVER validity codes: the byte-pure verdict and
// its code list are unchanged by any anchor comparison.
const (
	CodeCorpusAnchorMismatch    Code = "corpus-anchor-mismatch"
	CodeSubstrateAnchorMismatch Code = "substrate-anchor-mismatch"
)

// appendCode appends c to codes unless it is already present, preserving
// detection order (the first code is the deterministic primary code).
func appendCode(codes []Code, c Code) []Code {
	for _, existing := range codes {
		if existing == c {
			return codes
		}
	}
	return append(codes, c)
}
