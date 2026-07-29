package aee

// GATE 1 — coverage validity (spec:373-404). A consumption precondition, not
// an optional lint: a consumer that consumes result, credits any row, or
// applies either strength ordering MUST evaluate these first, and on failure
// the attestation is INVALID and its result MUST NOT be consumed.
//
// Everything here reads record payloads but never consumer policy, so it is
// a pure function of the carried statement (spec:375-378). It reads exactly
// one thing about signatures: how many entries the array carries, which needs
// no key material and so costs the layer none of its purity. Signature
// verification — the one trust-relative step — remains the evidence tier's
// separate question (tier.go); a signature that fails to verify is never a
// validity failure code.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Reserved payload members (spec:865-882).
const (
	memberRunBinding    = "aeeRunBinding"
	memberKind          = "aeeKind"
	memberMethod        = "aeeMethod"
	memberArmedAt       = "armedAt"
	memberPostureDigest = "aeePostureDigest"
	memberStillArmed    = "aeeStillArmed"
	memberDropCount     = "aeeDropCount"
	memberDropBound     = "aeeDropBound"

	// Optional arming-payload run-chaining members.
	memberRunSeq         = "aeeRunSeq"
	memberPrevRunBinding = "aeePrevRunBinding"
	memberChainScope     = "aeeChainScope"
	// Optional explicit binding-version declaration (read-first).
	memberBindingVersion = "aeeBindingVersion"
)

const jsonMediaTypeSuffix = "+json"

// recordState is the shared per-record decode state: the statement-level
// checks need every record's PAE bytes for the batchRoot; the per-row checks
// need the decoded payload of referenced records.
type recordState struct {
	payloadBytes []byte
	pae          []byte
	decodeErr    bool
}

// Gate1 evaluates coverage validity and returns every violation found, in a
// pinned deterministic order. It must only run on statements that passed
// GATE 0 (it relies on GATE 0's presence and digest-shape guarantees).
func Gate1(s *Statement) []Code {
	_, _, _, codes := gate1WithContext(s)
	return codes
}

// gate1WithContext runs GATE 1 and additionally returns the memoized artifacts
// it necessarily builds along the way -- the decoded per-record states, the
// derived run binding, and the parsed issuedAt -- so Evaluate can seal them
// into an EvalContext instead of DeriveTiers and CheckRecordSignatures each
// re-deriving them (the triple-recompute drift risk). Behavior is identical to
// the previous inline Gate1: the returned codes are unchanged.
func gate1WithContext(s *Statement) (states []recordState, binding string, issuedAt time.Time, codes []Code) {
	p := s.Predicate

	states, stCodes := checkRecordsStatementLevel(p)
	for _, c := range stCodes {
		codes = appendCode(codes, c)
	}

	// An out-of-range observationRefs index is a structural integrity fault on
	// ANY row, regardless of basis and including rows nothing normative reads,
	// fail-closed and independent of any gate. Checked before the substrate-row
	// path so an artifact-only statement with a dangling ref is still rejected.
	// Reserved for statements where records exist: with no records the
	// records-absent precedence owns the reject (a ref cannot resolve to a
	// record set that is not there).
	if len(p.Records) > 0 && anyObservationRefOutOfRange(p) {
		codes = appendCode(codes, CodeRefOutOfRange)
	}

	if !hasSubstrateRows(p) {
		return states, "", time.Time{}, codes
	}

	// Registry precedence pin 2: when observationRecords is absent entirely,
	// report records-absent; ref-out-of-range is reserved for statements
	// where records exist.
	if !p.RecordsPresent {
		return states, "", time.Time{}, appendCode(codes, CodeRecordsAbsent)
	}

	binding = deriveStatementBinding(s)
	var err error
	issuedAt, err = parseTimestamp(p.IssuedAt)
	if err != nil {
		// GATE 0 already rejected this; defensive only.
		return states, binding, issuedAt, appendCode(codes, CodeIssuedAtMalformed)
	}

	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.IsSubstrate() {
			continue
		}
		rowCodes, _ := checkSubstrateRow(p, row, states, binding, issuedAt)
		for _, c := range rowCodes {
			codes = appendCode(codes, c)
		}
	}
	return states, binding, issuedAt, codes
}

// checkRecordsStatementLevel runs the record-set checks that hold for the
// whole statement whenever observationRecords is non-empty, BEFORE any row
// logic: signature-entry presence (spec:845-847), batchRoot presence
// (spec:1005), duplicate-record rejection (spec:1013-1015), root recomputation
// (spec:1017-1019), and the orphaned-root case (a batchRoot with no records to
// recompute over, spec:1029-1032).
func checkRecordsStatementLevel(p *Predicate) ([]recordState, []Code) {
	var codes []Code
	states := make([]recordState, len(p.Records))

	if !p.RecordsPresent || len(p.Records) == 0 {
		if p.BatchRootPresent {
			codes = appendCode(codes, CodeBatchRootOrphaned)
		}
		return states, codes
	}

	// Envelope shape before payload bytes: a record's signatures member MUST
	// carry at least one entry. Checked here rather than at the tier because
	// counting array entries reads no key material, so the check keeps this
	// layer a pure function of the carried statement.
	//
	// Asked once over the whole record set, and asked BEFORE the decode loop
	// below rather than inside it. Both are load-bearing. The verify-then-read
	// discipline puts a record's signature ahead of its payload (spec:847-854),
	// so a record with no signature at all is settled before the bytes it
	// carries are read; and a count evaluated per record inside the loop would
	// make the reported code depend on which record in the array happened to
	// carry which fault, which no vector carrying a single fault can detect.
	// The corpus pins the ordering with bad-748.
	if anyRecordSignaturesEmpty(p) {
		codes = appendCode(codes, CodeRecordSignaturesEmpty)
	}

	decodeFailed := false
	leaves := make([][32]byte, len(p.Records))
	for i := range p.Records {
		payload, err := base64.StdEncoding.Strict().DecodeString(p.Records[i].PayloadB64)
		if err != nil {
			states[i].decodeErr = true
			decodeFailed = true
			codes = appendCode(codes, CodeRecordUndecodable)
			continue
		}
		states[i].payloadBytes = payload
		states[i].pae = PAE(p.Records[i].PayloadType, payload)
		leaves[i] = LeafHash(states[i].pae)
	}

	if !decodeFailed {
		seen := map[[32]byte]bool{}
		for _, leaf := range leaves {
			if seen[leaf] {
				codes = appendCode(codes, CodeDuplicateRecord)
				break
			}
			seen[leaf] = true
		}
		root := MerkleRoot(leaves)
		if !p.BatchRootPresent {
			codes = appendCode(codes, CodeBatchRootMissing)
		} else if p.BatchRoot != hex.EncodeToString(root[:]) {
			codes = appendCode(codes, CodeBatchRootMismatch)
		}
	}
	return states, codes
}

// anyRecordSignaturesEmpty reports whether any observation record carries no
// signature entry at all. A record is a DSSE envelope, and the spec requires
// its signatures member to carry at least one entry, so an absent member, an
// empty array and a value that is not an array are one fault: zero entries.
// All three land here, because a missing member decodes to a nil slice and
// RecordSignatures decodes a non-array to the same nil.
//
// What this does NOT do, stated plainly so nobody reads more into it: it
// proves nothing whatsoever about the signatures it counts. A producer who
// fills the array with plausible-looking garbage bytes passes it, and is
// caught only by real signature verification against a consumer-pinned key at
// GATE 2. The check converts "admits a statement carrying zero signatures"
// into "admits one whose signatures are structurally present but unchecked" —
// a narrow improvement, not a substitute for verification.
//
// It is worth having because the zero case is otherwise invisible at this
// layer. Stripping every signatures entry from every record leaves batchRoot
// unchanged (a leaf is H(0x00||PAE) and the PAE pre-image spans only
// payloadType and payload), leaves the statement valid, and leaves result at
// whatever it was; only the derived evidence tier drops. A consumer gating on
// result alone therefore admitted an entirely unsigned attestation. Being
// byte-pure, this closes the literal zero-signature case in every deployment,
// including ones that cannot do curve math at all.
func anyRecordSignaturesEmpty(p *Predicate) bool {
	for i := range p.Records {
		if len(p.Records[i].Signatures) == 0 {
			return true
		}
	}
	return false
}

// payloadAnalysis is the outcome of the byte-level checks every REFERENCED
// payload must pass (spec:854-863): canonical RFC 8785 + I-JSON RFC 7493
// object, +json media type, reserved members, run binding equality.
type payloadAnalysis struct {
	codes     []Code
	kind      string
	method    string
	obj       *jsonObject
	hasKind   bool
	hasMethod bool
}

func analyzePayload(rec *Record, state *recordState, binding string) payloadAnalysis {
	var a payloadAnalysis
	if state.decodeErr {
		a.codes = appendCode(a.codes, CodeRecordUndecodable)
		return a
	}

	v, err := parseJSONValue(state.payloadBytes)
	if err != nil {
		// Duplicate members and unsafe integers are the I-JSON profile
		// faults; any other parse failure means the payload is not a
		// parseable JSON value at all — the same covers-nothing class.
		a.codes = appendCode(a.codes, CodePayloadNotIJSON)
		return a
	}
	obj, ok := v.(*jsonObject)
	if !ok {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
		return a
	}
	a.obj = obj

	canon, err := Canonicalize(state.payloadBytes)
	if err != nil || !bytes.Equal(canon, state.payloadBytes) {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
	}
	// BMP-only string profile: a supplementary-plane member name anywhere in
	// the covering payload makes it cover nothing, the same handling as
	// non-canonical bytes. A payload can pass the byte-equality check above
	// under both the UTF-16 and the code-point member order when the two
	// orders happen to agree on its names; rejecting non-BMP names outright
	// removes the only inputs on which the two orders can disagree.
	if hasSupplementaryMemberName(obj) {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
	}
	if !strings.HasSuffix(rec.PayloadType, jsonMediaTypeSuffix) {
		a.codes = appendCode(a.codes, CodePayloadMediaType)
	}

	rb, hasRB := objString(obj, memberRunBinding)
	a.kind, a.hasKind = objString(obj, memberKind)
	a.method, a.hasMethod = objString(obj, memberMethod)
	if !hasRB || !a.hasKind || !a.hasMethod {
		a.codes = appendCode(a.codes, CodePayloadMissingReserved)
		return a
	}
	if rb != binding {
		a.codes = appendCode(a.codes, CodeRunBindingMismatch)
	}
	return a
}

// recordEval is a referenced record's covering evaluation: whether it
// satisfies its declared aeeKind's constraints (spec:867-893), and the
// kind-specific code to report when it does not. A record violating any
// constraint of its declared kind covers nothing (spec:884-887); a record
// whose kind is unrecognized covers nothing and is otherwise ignored
// (spec:971-973).
type recordEval struct {
	kind        string
	method      string
	valid       bool
	failCode    Code
	unknownKind bool
}

func evaluateKind(a payloadAnalysis, pinnedPosture string, armingPostures []string, issuedAt time.Time) recordEval {
	ev := recordEval{kind: a.kind, method: a.method}
	methodKnown := a.method == MethodIntercepted || a.method == MethodReconstructed

	switch a.kind {
	case KindInterception:
		// No kind-specific members; an out-of-vocabulary aeeMethod cannot
		// participate in the method cap, so the record covers nothing.
		ev.valid = methodKnown
		ev.failCode = CodePayloadMissingReserved
	case KindArming:
		ev.failCode = CodeArmingCoversNothing
		// Read-first binding-version declaration: an arming payload MAY carry an
		// explicit aeeBindingVersion. A verifier reads it before deriving and
		// rejects fail-closed (the record covers nothing) a value it does not
		// implement, distinguishably from a run-binding digest mismatch. Absent
		// defaults to the implemented version; the derivation is unchanged.
		if bv, ok := objString(a.obj, memberBindingVersion); ok && bv != BindingVersion {
			return ev
		}
		armedAt, hasArmedAt := objString(a.obj, memberArmedAt)
		posture, hasPosture := objString(a.obj, memberPostureDigest)
		if !hasArmedAt || !hasPosture || a.method != MethodIntercepted {
			return ev
		}
		// armedAt carries the timestamp profile issuedAt defines (spec:870-871), so
		// the same parse enforces it. A spelling outside the profile names a
		// valid instant no later than issuedAt and still makes the arming record
		// cover nothing, which is why the profile is part of the parse rather
		// than a separate test a later reader can forget to copy.
		t, err := parseTimestamp(armedAt)
		if err != nil || t.After(issuedAt) {
			return ev
		}
		if posture != pinnedPosture {
			return ev
		}
		if !armingChainSyntaxValid(a.obj) {
			return ev
		}
		ev.valid = true
	case KindSealed:
		ev.failCode = CodeSealedCoversNothing
		stillArmed, hasStillArmed := objBool(a.obj, memberStillArmed)
		dropCount, hasDropCount := objInt(a.obj, memberDropCount)
		posture, hasPosture := objString(a.obj, memberPostureDigest)
		if !hasStillArmed || !stillArmed || !hasDropCount || !hasPosture || a.method != MethodIntercepted {
			return ev
		}
		if dropCount != 0 {
			bound, hasBound := objInt(a.obj, memberDropBound)
			if !hasBound || dropCount < 0 || dropCount > bound {
				return ev
			}
		}
		// The two sealed posture equalities are jointly enforced: the seal's
		// posture must equal the pinned networkPosture digest AND every
		// referenced arming record's posture claim (spec:888-893).
		if posture != pinnedPosture {
			return ev
		}
		for _, ap := range armingPostures {
			if posture != ap {
				return ev
			}
		}
		ev.valid = true
	case KindExamination:
		ev.failCode = CodeExaminationCoversNothing
		ev.valid = a.method == MethodReconstructed
	default:
		ev.unknownKind = true
		ev.failCode = CodeRecordKindUnknownCoversNothing
	}
	return ev
}

// chainScopeVocabulary is the closed set of aeeChainScope dimension tokens.
// Each token pins a projection to a value already carried on the wire
// (subject -> subject[0].digest.sha256, corpus ->
// observationEnvironment.corpus.digest, networkPosture ->
// networkPosture.digest.sha256). Minor versions MAY append tokens; an
// unrecognized token fails closed.
var chainScopeVocabulary = map[string]bool{
	"subject":        true,
	"corpus":         true,
	"networkPosture": true,
}

// armingChainSyntaxValid checks the optional run-chaining members an arming
// payload MAY carry: aeeRunSeq, aeePrevRunBinding, aeeChainScope. They are
// syntax-checked here in the reserved-member walk and nothing else normative
// reads them (the coverage validity requirements, the result recompute, and
// the evidence tier are unchanged); their cross-attestation gap/fork
// semantics are consumer policy over whatever set a producer publishes.
//
// Syntax: aeeRunSeq is a positive safe-range integer; aeeChainScope is a
// duplicate-free array of tokens from the closed chainScopeVocabulary, sorted
// in observationVocabulary.labels canonical order (UTF-16 code-unit),
// REQUIRED whenever aeeRunSeq is present; aeePrevRunBinding is a lowercase
// 64-hex string, present exactly when aeeRunSeq is greater than 1 (a genesis
// record, aeeRunSeq 1, carries no predecessor). A chain member present without
// aeeRunSeq is rejected fail-closed: the members are defined only as a set
// anchored on the sequence number, and a reserved aee member with
// unsatisfiable syntax can only weaken coverage, never create it.
func armingChainSyntaxValid(obj *jsonObject) bool {
	_, seqPresent := obj.values[memberRunSeq]
	_, prevPresent := obj.values[memberPrevRunBinding]
	_, scopePresent := obj.values[memberChainScope]
	if !seqPresent {
		return !prevPresent && !scopePresent
	}
	seq, seqIsInt := objInt(obj, memberRunSeq)
	if !seqIsInt || seq < 1 {
		return false
	}
	scope, ok := objStringArray(obj, memberChainScope)
	if !ok {
		return false
	}
	for _, tok := range scope {
		if !chainScopeVocabulary[tok] {
			return false
		}
	}
	if !isSortedNoDuplicates(scope) {
		return false
	}
	if seq == 1 {
		return !prevPresent
	}
	prev, ok := objString(obj, memberPrevRunBinding)
	return ok && IsLowerHex64(prev)
}

// anyObservationRefOutOfRange reports whether any row, regardless of basis,
// carries a present, well-formed observationRefs index that is out of range
// for observationRecords. An out-of-range index is a structural integrity
// fault that makes the statement invalid, fail-closed and independent of any
// gate (spec: observationRefs field definition). Malformed refs (RefsErr) are
// a separate code and are skipped here.
func anyObservationRefOutOfRange(p *Predicate) bool {
	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.RefsPresent || row.RefsErr != nil {
			continue
		}
		for _, idx := range row.Refs {
			if idx < 0 || idx >= len(p.Records) {
				return true
			}
		}
	}
	return false
}

// classRequirement is one class-match requirement of a row (spec:385-391).
type classRequirement struct {
	kind        string
	genericCode Code
}

// checkSubstrateRow evaluates one basis: substrate row. It returns the
// row's validity codes and, when the row is valid, the indexes of its
// covering records (the referenced records of the class(es) the row's
// class-match rule requires — extras are payload-checked but neither cap
// nor tier-gate).
func checkSubstrateRow(p *Predicate, row *Row, states []recordState, binding string, issuedAt time.Time) ([]Code, []int) {
	var codes []Code
	voc := p.Env.Vocabulary

	// A fail-closed substrate row (out-of-vocabulary label, or missing or
	// out-of-vocabulary method) cannot satisfy the class-match requirement
	// and is therefore invalid (spec:427-431).
	labelCaught := isCaughtLabel(voc, row.ContainmentObserved)
	labelClean := isCleanLabel(voc, row.ContainmentObserved)
	methodValid := row.Method != nil && (*row.Method == MethodIntercepted || *row.Method == MethodReconstructed)
	if (!labelCaught && !labelClean) || !methodValid {
		return appendCode(codes, CodeFailClosedSubstrateRow), nil
	}

	// observationRefs shape (spec:383-384).
	if !row.RefsPresent {
		return appendCode(codes, CodeRefsEmpty), nil
	}
	if row.RefsErr != nil {
		return appendCode(codes, CodeRefMalformed), nil
	}
	if len(row.Refs) == 0 {
		return appendCode(codes, CodeRefsEmpty), nil
	}
	uniqueRefs := make([]int, 0, len(row.Refs))
	seen := map[int]bool{}
	for _, idx := range row.Refs {
		if idx >= len(p.Records) {
			codes = appendCode(codes, CodeRefOutOfRange)
			continue
		}
		if !seen[idx] {
			seen[idx] = true
			uniqueRefs = append(uniqueRefs, idx)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Every referenced payload must pass the byte-level checks (spec:392-395).
	analyses := map[int]payloadAnalysis{}
	for _, idx := range uniqueRefs {
		a := analyzePayload(&p.Records[idx], &states[idx], binding)
		analyses[idx] = a
		for _, c := range a.codes {
			codes = appendCode(codes, c)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Kind constraints + class-match (spec:884-893, 385-391).
	pinnedPosture := p.Env.NetworkPosture.Sha256()
	var armingPostures []string
	for _, idx := range uniqueRefs {
		a := analyses[idx]
		if a.kind == KindArming {
			if posture, ok := objString(a.obj, memberPostureDigest); ok {
				armingPostures = append(armingPostures, posture)
			}
		}
	}

	evals := map[int]recordEval{}
	unknownSeen := false
	for _, idx := range uniqueRefs {
		ev := evaluateKind(analyses[idx], pinnedPosture, armingPostures, issuedAt)
		evals[idx] = ev
		if ev.unknownKind {
			unknownSeen = true
		}
	}

	var reqs []classRequirement
	switch {
	case *row.Method == MethodReconstructed:
		reqs = append(reqs, classRequirement{KindExamination, CodeReconstructedRowUncovered})
	case labelCaught: // method: intercepted
		reqs = append(reqs, classRequirement{KindInterception, CodeCaughtRowUncovered})
	default: // clean row, method: intercepted
		reqs = append(reqs, classRequirement{KindArming, CodeCleanRowUncovered})
		reqs = append(reqs, classRequirement{KindSealed, CodeCleanRowUncovered})
	}

	var covering []int
	for _, req := range reqs {
		satisfied := false
		candidateFail := Code("")
		for _, idx := range uniqueRefs {
			ev := evals[idx]
			if ev.kind != req.kind {
				continue
			}
			if ev.valid {
				satisfied = true
				covering = append(covering, idx)
			} else if candidateFail == "" {
				candidateFail = ev.failCode
			}
		}
		if satisfied {
			continue
		}
		switch {
		case candidateFail != "":
			codes = appendCode(codes, candidateFail)
		case unknownSeen:
			codes = appendCode(codes, CodeRecordKindUnknownCoversNothing)
		default:
			codes = appendCode(codes, req.genericCode)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Method cap (spec:396-397): the row's method is no stronger than the
	// weakest signed aeeMethod across its COVERING records (reconstructed is
	// weaker than intercepted). Registry precedence pin 3: records that
	// cover nothing do not participate in the cap.
	capMethod := MethodIntercepted
	for _, idx := range covering {
		if evals[idx].method == MethodReconstructed {
			capMethod = MethodReconstructed
		}
	}
	if *row.Method == MethodIntercepted && capMethod == MethodReconstructed {
		codes = appendCode(codes, CodeMethodCapExceeded)
	}
	if len(codes) > 0 {
		return codes, nil
	}
	return nil, covering
}

// objString reads a string member from a parsed payload object.
func objString(obj *jsonObject, key string) (string, bool) {
	if obj == nil {
		return "", false
	}
	v, ok := obj.values[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// objStringArray reads an array-of-strings member from a parsed payload
// object. ok is false if the member is absent or is not a JSON array whose
// every element is a string.
func objStringArray(obj *jsonObject, key string) ([]string, bool) {
	if obj == nil {
		return nil, false
	}
	v, ok := obj.values[key]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, el := range arr {
		s, ok := el.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// objBool reads a boolean member; a string "true" is NOT a boolean.
func objBool(obj *jsonObject, key string) (bool, bool) {
	if obj == nil {
		return false, false
	}
	v, ok := obj.values[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// objInt reads an integer member; non-integer numbers are rejected.
func objInt(obj *jsonObject, key string) (int64, bool) {
	if obj == nil {
		return 0, false
	}
	v, ok := obj.values[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}
