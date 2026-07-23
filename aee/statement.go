package aee

// GATE 0 — statement well-formedness. Runs FIRST at both verify and emit:
// the emit seam refuses to sign a statement this gate rejects, so a producer
// pipeline cannot emit what the suite rejects.
//
// Everything here is a pure function of carried bytes: no signatures, no
// consumer policy. Checks that need the observation records themselves
// (batchRoot, duplicate records, per-row coverage) live in GATE 1.

import (
	"bytes"
	"sort"
	"time"
)

const rejectedSnakeCaseSpelling = "does_not_assert"

// Gate0 evaluates statement well-formedness and returns every violation
// found, in a pinned deterministic order (the first code is the primary
// code). An empty slice means the statement passed GATE 0.
func Gate0(s *Statement) []Code {
	var codes []Code
	p := s.Predicate

	// 1. Statement envelope types (spec:125,129; both halves of condition
	//    coverage: _type and predicateType).
	if s.Type != StatementType {
		codes = appendCode(codes, CodeStatementTypeUnsupported)
	}
	if s.PredicateType != PredicateType {
		codes = appendCode(codes, CodePredicateTypeUnsupported)
	}

	// 2. Faults recorded while decoding members.
	for _, c := range s.ParseCodes {
		codes = appendCode(codes, c)
	}

	// 3. Rejected snake_case spelling: single canonicalization per content
	//    (spec:655-660).
	if _, ok := p.Raw[rejectedSnakeCaseSpelling]; ok {
		codes = appendCode(codes, CodeMemberSpelling)
	}

	// 4. result vocabulary (spec:220-222).
	if !p.ResultPresent || !isResultToken(p.Result) {
		codes = appendCode(codes, CodeResultVocabulary)
	}

	// 5. observationEnvironment members (spec:290-303). observationVocabulary
	//    absence carries its own code; the other four report
	//    environment-incomplete.
	env := p.Env
	if env == nil {
		codes = appendCode(codes, CodeEnvironmentIncomplete)
		codes = appendCode(codes, CodeVocabularyMissing)
	} else {
		if env.Substrate == nil || env.Corpus == nil || env.CatchPolicy == nil || env.NetworkPosture == nil {
			codes = appendCode(codes, CodeEnvironmentIncomplete)
		}
		if env.Vocabulary == nil {
			codes = appendCode(codes, CodeVocabularyMissing)
		}
	}

	// 6. Vocabulary shape, subset, digest (spec:300-311).
	if env != nil && env.Vocabulary != nil {
		codes = gate0Vocabulary(env.Vocabulary, codes)
	}

	// 7. Corpus manifest digest + duplicate attack ids (spec:294-297, 314-316).
	if env != nil && env.Corpus != nil {
		codes = gate0Corpus(env.Corpus, codes)
	}

	// 8. coverage presence (spec:318-325).
	if !p.CoveragePresent {
		codes = appendCode(codes, CodeCoverageMissing)
	}

	// 9. attackResults presence (required member, spec:327).
	if !p.RowsPresent {
		codes = appendCode(codes, CodeStatementMalformed)
	}

	// 10. Per-row actualLayer altitude (spec:541-559): a missing member is a
	//     malformed statement; a clean row must carry the literal "none".
	vocabOK := env != nil && env.Vocabulary != nil && !containsVocabularyCodes(codes)
	for i := range p.Rows {
		row := &p.Rows[i]
		if row.ActualLayer == nil {
			codes = appendCode(codes, CodeMissingActualLayer)
			continue
		}
		if vocabOK && isCleanLabel(env.Vocabulary, row.ContainmentObserved) && *row.ActualLayer != ActualLayerNone {
			codes = appendCode(codes, CodeCleanRowLayerNotNone)
		}
	}

	// 11. Coverage integrity at attack granularity (spec:350-353): every row
	//     attackId appears in the manifest, and the union of row attackIds
	//     exactly equals the manifest's attackIds for the assessed classes.
	if env != nil && env.Corpus != nil && env.Corpus.Classes != nil && p.Coverage != nil {
		codes = gate0CoverageIntegrity(p, env, codes)
	}

	// 12. Substrate-carrying statements: runEntropy, subject cardinality,
	//     and the six binding digest inputs (spec:72-104, 311-313).
	if hasSubstrateRows(p) {
		codes = gate0SubstrateBindingInputs(s, codes)
	}

	// 13. issuedAt (spec:662-664).
	if !p.IssuedAtPresent {
		codes = appendCode(codes, CodeIssuedAtMissing)
	} else if _, err := time.Parse(time.RFC3339, p.IssuedAt); err != nil {
		codes = appendCode(codes, CodeIssuedAtMalformed)
	}

	return codes
}

func isResultToken(v string) bool {
	return v == ResultPass || v == ResultDegraded || v == ResultFail
}

func containsVocabularyCodes(codes []Code) bool {
	for _, c := range codes {
		switch c {
		case CodeVocabularyMissing, CodeVocabularyNotCanonical, CodeVocabularyCaughtNotSubset, CodeVocabularyDigestMismatch:
			return true
		}
	}
	return false
}

func gate0Vocabulary(v *Vocabulary, codes []Code) []Code {
	if !v.LabelsPresent || !v.CaughtPresent {
		return appendCode(codes, CodeVocabularyNotCanonical)
	}
	if !isSortedNoDuplicates(v.Labels) || !isSortedNoDuplicates(v.Caught) {
		codes = appendCode(codes, CodeVocabularyNotCanonical)
	}
	// BMP-only string profile: a supplementary-plane labels/caught entry
	// makes the statement malformed, the same handling as non-canonical
	// bytes. The UTF-16 sort rule above stays in force as defense in depth;
	// this rejection removes the only inputs on which a UTF-16 rail and a
	// code-point rail could order the vocabulary differently.
	if !vocabularyStringsBMPOnly(v.Labels, v.Caught) {
		codes = appendCode(codes, CodeVocabularyNotCanonical)
	}
	labelSet := stringSet(v.Labels)
	for _, c := range v.Caught {
		if !labelSet[c] {
			codes = appendCode(codes, CodeVocabularyCaughtNotSubset)
			break
		}
	}
	want := SHA256Hex(canonicalVocabulary(v.Labels, v.Caught))
	got := ""
	if v.Digest != nil {
		got = v.Digest["sha256"]
	}
	if got != want {
		codes = appendCode(codes, CodeVocabularyDigestMismatch)
	}
	return codes
}

// canonicalVocabulary builds the JCS bytes of the digest pre-image object
// {"caught": [...], "labels": [...]} (spec:305-307).
func canonicalVocabulary(labels, caught []string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"caught":`)
	appendStringArray(&buf, caught)
	buf.WriteString(`,"labels":`)
	appendStringArray(&buf, labels)
	buf.WriteByte('}')
	return buf.Bytes()
}

func appendStringArray(buf *bytes.Buffer, ss []string) {
	buf.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			buf.WriteByte(',')
		}
		appendJCSString(buf, s)
	}
	buf.WriteByte(']')
}

func gate0Corpus(c *Corpus, codes []Code) []Code {
	if len(c.ManifestRaw) == 0 {
		return appendCode(codes, CodeEnvironmentIncomplete)
	}
	canon, err := Canonicalize(c.ManifestRaw)
	if err != nil {
		return appendCode(codes, CodeStatementMalformed)
	}
	if c.Sha256() != SHA256Hex(canon) {
		codes = appendCode(codes, CodeCorpusDigestMismatch)
	}
	// An attackId MUST NOT appear under more than one class (spec:296-297);
	// a duplicate inside one class array is the same integrity fault.
	seen := map[string]bool{}
	for _, class := range sortedKeys(c.Classes) {
		for _, id := range c.Classes[class] {
			if seen[id] {
				codes = appendCode(codes, CodeManifestDuplicateAttack)
			}
			seen[id] = true
		}
	}
	return codes
}

func gate0CoverageIntegrity(p *Predicate, env *Environment, codes []Code) []Code {
	inManifest := map[string]bool{}
	for _, ids := range env.Corpus.Classes {
		for _, id := range ids {
			inManifest[id] = true
		}
	}
	// Coverage MUST be an exhaustive, disjoint partition of the manifest's
	// classes across assessedClasses / outOfScope / routedElsewhere, each a
	// real manifest class (spec:320-325, 350-353). Enforcing this closes a
	// fail-open: without it a producer drops a failing class from all three
	// sets (silently omitting it while still reporting pass), or pads
	// assessedClasses with a fabricated class the manifest never carried.
	manifestClasses := map[string]bool{}
	for c := range env.Corpus.Classes {
		manifestClasses[c] = true
	}
	classAcct := map[string]int{}
	for _, c := range p.Coverage.AssessedClasses {
		classAcct[c]++
	}
	for c := range p.Coverage.OutOfScope {
		classAcct[c]++
	}
	for c := range p.Coverage.RoutedElsewhere {
		classAcct[c]++
	}
	partitionOK := true
	for c, n := range classAcct {
		if n != 1 || !manifestClasses[c] { // overlap across the three sets, or not a manifest class
			partitionOK = false
		}
	}
	for c := range manifestClasses {
		if classAcct[c] != 1 { // a manifest class left unaccounted, or double-counted
			partitionOK = false
		}
	}
	if !partitionOK {
		codes = appendCode(codes, CodeCoverageIncomplete)
	}

	expected := map[string]bool{}
	for _, class := range p.Coverage.AssessedClasses {
		for _, id := range env.Corpus.Classes[class] {
			expected[id] = true
		}
	}
	rowIDs := map[string]bool{}
	for i := range p.Rows {
		id := p.Rows[i].AttackID
		rowIDs[id] = true
		if !inManifest[id] {
			codes = appendCode(codes, CodeRowAttackUnknown)
		}
	}
	if !sameStringSet(rowIDs, expected) {
		codes = appendCode(codes, CodeCoverageIncomplete)
	}
	return codes
}

func gate0SubstrateBindingInputs(s *Statement, codes []Code) []Code {
	p := s.Predicate
	env := p.Env

	// runEntropy is required exactly when any row carries basis: substrate
	// (spec:311-313). Its absence reports its member code, never a binding
	// mismatch (registry precedence pin 1).
	if env == nil || env.RunEntropy == nil {
		codes = appendCode(codes, CodeRunEntropyMissing)
	} else if !IsLowerHex64(env.RunEntropy.Sha256()) {
		codes = appendCode(codes, CodeDigestNotCanonical)
	}

	// subject MUST contain exactly one entry (spec:82-84). Artifact-only
	// multi-subject is an open spec question and is deliberately not
	// enforced outside substrate-carrying statements.
	if len(s.Subject) != 1 {
		codes = appendCode(codes, CodeSubjectCardinality)
	}
	if len(s.Subject) >= 1 {
		sha, ok := s.Subject[0].Digest["sha256"]
		if !ok {
			codes = appendCode(codes, CodeSubjectSha256Missing)
		} else if !IsLowerHex64(sha) {
			codes = appendCode(codes, CodeDigestNotCanonical)
		}
	}

	// The remaining binding digest inputs must be lowercase 64-hex
	// (spec:82-85). Absent parent members were already reported as
	// environment-incomplete.
	if env != nil {
		for _, digest := range []string{
			env.CatchPolicy.Sha256(),
			env.Corpus.Sha256(),
			env.NetworkPosture.Sha256(),
			env.Substrate.Sha256(),
		} {
			if digest != "" && !IsLowerHex64(digest) {
				codes = appendCode(codes, CodeDigestNotCanonical)
			}
		}
	}
	return codes
}

func hasSubstrateRows(p *Predicate) bool {
	for i := range p.Rows {
		if p.Rows[i].IsSubstrate() {
			return true
		}
	}
	return false
}

func isCleanLabel(v *Vocabulary, label string) bool {
	return stringSet(v.Labels)[label] && !stringSet(v.Caught)[label]
}

func isCaughtLabel(v *Vocabulary, label string) bool {
	return stringSet(v.Caught)[label]
}

func vocabularyStringsBMPOnly(labels, caught []string) bool {
	for _, arr := range [][]string{labels, caught} {
		for _, s := range arr {
			if !isBMPOnly(s) {
				return false
			}
		}
	}
	return true
}

func isSortedNoDuplicates(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if !utf16Less(ss[i-1], ss[i]) {
			return false
		}
	}
	return true
}

func stringSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
