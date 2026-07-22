package aee

// GATE 1 — coverage validity (spec:234-261). A consumption precondition, not
// an optional lint: a consumer that consumes result, credits any row, or
// applies either strength ordering MUST evaluate these first, and on failure
// the attestation is INVALID and its result MUST NOT be consumed.
//
// Everything here reads record payloads but never signatures or consumer
// policy, so it is a pure function of the carried statement (spec:236-238).
// Signature verification — the one trust-relative step — is the evidence
// tier's separate question (tier.go); a signature failure is never a
// validity failure code.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Reserved payload members (spec:583-599).
const (
	memberRunBinding    = "aeeRunBinding"
	memberKind          = "aeeKind"
	memberMethod        = "aeeMethod"
	memberArmedAt       = "armedAt"
	memberPostureDigest = "aeePostureDigest"
	memberStillArmed    = "aeeStillArmed"
	memberDropCount     = "aeeDropCount"
	memberDropBound     = "aeeDropBound"
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
	issuedAt, err = time.Parse(time.RFC3339, p.IssuedAt)
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
// logic: batchRoot presence (spec:627), duplicate-record rejection
// (spec:635-637), root recomputation (spec:639-641), and the orphaned-root
// case (a batchRoot with no records to recompute over, spec:645-648).
func checkRecordsStatementLevel(p *Predicate) ([]recordState, []Code) {
	var codes []Code
	states := make([]recordState, len(p.Records))

	if !p.RecordsPresent || len(p.Records) == 0 {
		if p.BatchRootPresent {
			codes = appendCode(codes, CodeBatchRootOrphaned)
		}
		return states, codes
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

// payloadAnalysis is the outcome of the byte-level checks every REFERENCED
// payload must pass (spec:249-252): canonical RFC 8785 + I-JSON RFC 7493
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
// satisfies its declared aeeKind's constraints (spec:583-611), and the
// kind-specific code to report when it does not. A record violating any
// constraint of its declared kind covers nothing (spec:601-604); a record
// whose kind is unrecognized covers nothing and is otherwise ignored
// (spec:614-618).
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
		armedAt, hasArmedAt := objString(a.obj, memberArmedAt)
		posture, hasPosture := objString(a.obj, memberPostureDigest)
		if !hasArmedAt || !hasPosture || a.method != MethodIntercepted {
			return ev
		}
		t, err := time.Parse(time.RFC3339, armedAt)
		if err != nil || t.After(issuedAt) {
			return ev
		}
		if posture != pinnedPosture {
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
		// referenced arming record's posture claim (spec:605-610).
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

// classRequirement is one class-match requirement of a row (spec:243-248).
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
	// and is therefore invalid (spec:263-271).
	labelCaught := isCaughtLabel(voc, row.ContainmentObserved)
	labelClean := isCleanLabel(voc, row.ContainmentObserved)
	methodValid := row.Method != nil && (*row.Method == MethodIntercepted || *row.Method == MethodReconstructed)
	if (!labelCaught && !labelClean) || !methodValid {
		return appendCode(codes, CodeFailClosedSubstrateRow), nil
	}

	// observationRefs shape (spec:241-242).
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

	// Every referenced payload must pass the byte-level checks (spec:249-252).
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

	// Kind constraints + class-match (spec:243-248, 583-611).
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

	// Method cap (spec:253-254): the row's method is no stronger than the
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
