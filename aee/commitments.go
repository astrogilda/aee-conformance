package aee

// The coverage validity requirements 0.7 adds (spec:569-609). They sit apart
// from the per-row requirements in validity.go for a reason the specification
// states in the same sentence that introduces them: they hold on the STATEMENT,
// or on every row rather than only on a basis: substrate row. The per-row gate
// runs under `if !row.IsSubstrate() { continue }`, so a rule written there
// would silently acquire the scope that loop has, which is the scope three of
// the five are specifically not written to.
//
// None of these reads a signature or a key, so the layer stays a pure function
// of the carried statement, exactly as the requirements beside them are.

import (
	"bytes"
	"encoding/hex"
	"sort"
	"time"
)

// recordKinds decodes each carried record far enough to read its aeeKind, and
// nothing further. A record whose payload did not decode, does not parse as an
// I-JSON object, or carries no string aeeKind yields "", which no rule below
// matches: those faults are already reported by the paths that own them, and
// naming them again here would give a vector a second code for one fault.
func recordKinds(p *Predicate, states []recordState) []string {
	kinds := make([]string, len(p.Records))
	for i := range p.Records {
		if states[i].decodeErr {
			continue
		}
		v, err := parseJSONValue(states[i].payloadBytes)
		if err != nil {
			continue
		}
		obj, ok := v.(*jsonObject)
		if !ok {
			continue
		}
		if kind, ok := objString(obj, memberKind); ok {
			kinds[i] = kind
		}
	}
	return kinds
}

// payloadObject re-parses one record's payload. Callers have already
// established through recordKinds that the bytes parse to an object.
func payloadObject(state *recordState) *jsonObject {
	v, err := parseJSONValue(state.payloadBytes)
	if err != nil {
		return nil
	}
	obj, _ := v.(*jsonObject)
	return obj
}

// rowResolves reports whether the row resolves at least one in-range
// observationRefs index to a record of the named kind. A row with a malformed
// refs member resolves nothing here: ref-malformed owns that fault.
func rowResolves(row *Row, kinds []string, kind string) bool {
	if !row.RefsPresent || row.RefsErr != nil {
		return false
	}
	for _, idx := range row.Refs {
		if idx >= 0 && idx < len(kinds) && kinds[idx] == kind {
			return true
		}
	}
	return false
}

// gate1CommitmentsAnyBasis evaluates the requirements that hold on a statement
// of ANY basis. Three of the five are written over every row rather than only
// over a basis: substrate row, so they run before the substrate-row path
// returns and they never read the derived run binding -- which an
// artifact-only statement has no obligation to make derivable, since
// runEntropy is required exactly when some row declares that basis.
func gate1CommitmentsAnyBasis(p *Predicate, states []recordState) []Code {
	if !p.RecordsPresent || len(p.Records) == 0 {
		// With no records there is no interception to contradict or to orphan,
		// and a pinned row resolving nothing is already refused by the
		// existence part below, which reads the row rather than the record set.
		return attributionBindings(p, states, nil)
	}
	kinds := recordKinds(p, states)
	var codes []Code
	codes = appendCodes(codes, cleanRowsContradicted(p, kinds))
	codes = appendCodes(codes, interceptionsOrphaned(p, kinds))
	codes = appendCodes(codes, attributionBindings(p, states, kinds))
	return codes
}

// gate1CommitmentsSubstrate evaluates the requirements that read the derived
// run binding, so it runs only on the path that has one.
func gate1CommitmentsSubstrate(p *Predicate, states []recordState, binding string, issuedAt time.Time) []Code {
	if !p.RecordsPresent || len(p.Records) == 0 {
		// A substrate row with no records at all is already owned by
		// records-absent, which fires first and says the same thing about more
		// of the statement.
		return nil
	}
	kinds := recordKinds(p, states)
	var codes []Code
	codes = appendCodes(codes, sealsCommitToCarriedSet(p, states, kinds, binding))
	codes = appendCodes(codes, sealedRecordPresent(p, states, kinds, binding, issuedAt))
	codes = appendCodes(codes, sealNamedAttacksCaught(p, states, kinds, binding))
	codes = appendCodes(codes, assessedSetDeclared(p, states, kinds, binding))
	return codes
}

func appendCodes(dst []Code, src []Code) []Code {
	for _, c := range src {
		dst = appendCode(dst, c)
	}
	return dst
}

// cleanRowsContradicted implements the first requirement: a clean row resolves
// no observationRefs index to an interception record (spec:574-579). Stated
// over every row, so the loop reads no basis.
func cleanRowsContradicted(p *Predicate, kinds []string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		if !isCleanLabel(voc, row.ContainmentObserved) {
			continue
		}
		if rowResolves(row, kinds, KindInterception) {
			return []Code{CodeCleanRowContradicted}
		}
	}
	return nil
}

// interceptionsOrphaned implements the second: every carried interception
// record is resolved by at least one observationRefs index on a CAUGHT row
// (spec:580-585). One record MAY be resolved by several rows, so the test is
// existence and never a count.
func interceptionsOrphaned(p *Predicate, kinds []string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	resolved := make([]bool, len(p.Records))
	for i := range p.Rows {
		row := &p.Rows[i]
		if !isCaughtLabel(voc, row.ContainmentObserved) {
			continue
		}
		if !row.RefsPresent || row.RefsErr != nil {
			continue
		}
		for _, idx := range row.Refs {
			if idx >= 0 && idx < len(resolved) {
				resolved[idx] = true
			}
		}
	}
	for i := range p.Records {
		if kinds[i] == KindInterception && !resolved[i] {
			return []Code{CodeInterceptionRecordOrphaned}
		}
	}
	return nil
}

// observedSetDigest recomputes the value a sealed record's aeeObservedSet
// commits to (spec:1346-1351): the lowercase 64-hex SHA-256 of the RFC 8785
// canonicalization of the duplicate-free array, sorted ascending by UTF-16
// code unit, of the leaf hashes of every interception and examination record.
//
// The entries are lowercase hex, so they are ASCII, so their UTF-16 code-unit
// order and their byte order are the same order. sort.Strings is therefore the
// rule and not an approximation of it -- but the equivalence is a property of
// the value space rather than of the sort, which is why it is written down
// here rather than assumed at the call site.
func observedSetDigest(p *Predicate, states []recordState, kinds []string) string {
	seen := map[string]bool{}
	leaves := make([]string, 0, len(p.Records))
	for i := range p.Records {
		if kinds[i] != KindInterception && kinds[i] != KindExamination {
			continue
		}
		h := LeafHash(states[i].pae)
		leaf := hex.EncodeToString(h[:])
		if seen[leaf] {
			continue
		}
		seen[leaf] = true
		leaves = append(leaves, leaf)
	}
	sort.Strings(leaves)
	var buf bytes.Buffer
	appendStringArray(&buf, leaves)
	return SHA256Hex(buf.Bytes())
}

// sealsCommitToCarriedSet implements the fourth: aeeObservedSet on every
// carried sealed record equals the recompute (spec:595-599).
//
// A seal whose member is absent or is not lowercase 64-hex is NOT reported
// here. That record covers nothing by its own kind's constraints, which is a
// different fault with a different code, and reporting both would give one
// mutation two codes.
func sealsCommitToCarriedSet(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	want := ""
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		got, ok := objString(obj, memberObservedSet)
		if !ok || !IsLowerHex64(got) {
			continue
		}
		if want == "" {
			want = observedSetDigest(p, states, kinds)
		}
		if got != want {
			return []Code{CodeObservedSetMismatch}
		}
	}
	return nil
}

// sealedRecordPresent implements the third: a statement carrying at least one
// basis: substrate row carries at least one sealed record satisfying every
// constraint of its kind and whose aeeRunBinding equals the derived binding,
// whether or not any row resolves an index to it (spec:586-594).
func sealedRecordPresent(p *Predicate, states []recordState, kinds []string, binding string, issuedAt time.Time) []Code {
	if !hasSubstrateRows(p) {
		return nil
	}
	pinnedPosture := p.Env.NetworkPosture.Sha256()
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		a := analyzePayload(&p.Records[i], &states[i], binding)
		if len(a.codes) > 0 {
			continue
		}
		if evaluateKind(a, pinnedPosture, nil, issuedAt, declaredAttackIDs(p)).valid {
			return nil
		}
	}
	return []Code{CodeSealedRecordAbsent}
}

// declaredAttackIDs is the set of attack identifiers the carried
// corpus.manifest.classes declares.
func declaredAttackIDs(p *Predicate) map[string]bool {
	declared := map[string]bool{}
	if p.Env == nil || p.Env.Corpus == nil {
		return declared
	}
	for _, ids := range p.Env.Corpus.Classes {
		for _, id := range ids {
			declared[id] = true
		}
	}
	return declared
}

// attackIDArrayOK is the shared shape rule for the two arrays of attack
// identifiers 0.7 adds, aeeAssessedAttacks and aeeObservedAttacks
// (spec:1316-1318, 1384-1386): duplicate-free, sorted ascending by UTF-16 code
// unit, every entry an identifier the carried manifest declares. The EMPTY
// array satisfies it, which is deliberate on the seal: a substrate holding no
// correspondence declares that on the wire rather than by omission.
func attackIDArrayOK(attacks []string, declared map[string]bool) bool {
	if !isSortedNoDuplicates(attacks) {
		return false
	}
	for _, id := range attacks {
		if !declared[id] {
			return false
		}
	}
	return true
}

// sealNamedAttacksCaught implements the aeeObservedAttacks statement rule
// (spec:1386-1389): for every identifier the array names, the
// statement MUST carry a row with that attackId whose containmentObserved is
// in the carried caught set.
//
// The rule reads in ONE direction. A seal omitting an attack licenses nothing
// and in particular does not oblige a clean row, which is what makes a lower
// bound sound without asking the substrate to resolve every ambiguous case.
func sealNamedAttacksCaught(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	caughtIDs := map[string]bool{}
	for i := range p.Rows {
		if isCaughtLabel(voc, p.Rows[i].ContainmentObserved) {
			caughtIDs[p.Rows[i].AttackID] = true
		}
	}
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		attacks, ok := objStringArray(obj, memberObservedAttacks)
		if !ok || !attackIDArrayOK(attacks, declaredAttackIDs(p)) {
			continue
		}
		for _, id := range attacks {
			if !caughtIDs[id] {
				return []Code{CodeObservedAttackUncaught}
			}
		}
	}
	return nil
}

// assessedSetDeclared implements the aeeAssessedAttacks statement rule
// (spec:1318-1320): the union of the manifest's identifiers for
// the carried coverage.assessedClasses MUST be a subset of the array the
// arming record signed before injection.
//
// A subset and not an equality. An equality would refuse the honest run that
// declared two classes, lost one part-way and disclosed the loss, and would
// buy, against the withdrawal it appears to catch, only the version of that
// withdrawal that leaves the arming record in place.
func assessedSetDeclared(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	if p.Coverage == nil || p.Env == nil || p.Env.Corpus == nil {
		return nil
	}
	assessed := map[string]bool{}
	for _, class := range p.Coverage.AssessedClasses {
		for _, id := range p.Env.Corpus.Classes[class] {
			assessed[id] = true
		}
	}
	for i := range p.Records {
		if kinds[i] != KindArming {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		declared, ok := objStringArray(obj, memberAssessedAttacks)
		if !ok || !attackIDArrayOK(declared, declaredAttackIDs(p)) {
			continue
		}
		declaredSet := stringSet(declared)
		for id := range assessed {
			if !declaredSet[id] {
				return []Code{CodeAssessedSetExceedsDeclaration}
			}
		}
	}
	return nil
}

// attributionBindings implements the fifth requirement (spec:600-609), in the
// three parts the specification writes it in. The parts are checked in the
// order they are stated, and the existence part is checked FIRST because it is
// the part the other two are vacuous without: a universally quantified rule
// over an empty set is true, so a producer that deletes the interception
// records keeps the stronger label unless something asks whether any remain.
func attributionBindings(p *Predicate, states []recordState, kinds []string) []Code {
	for i := range p.Rows {
		row := &p.Rows[i]
		if row.Attribution == nil || *row.Attribution != AttributionPinned {
			continue
		}
		if !rowResolves(row, kinds, KindInterception) {
			return []Code{CodeAttributionPinnedRecordless}
		}
		expected := expectedFor(p, row.AttackID)
		if len(expected) == 0 {
			return []Code{CodeAttributionUnpinnable}
		}
		if code := pinMatches(p, row, states, kinds, expected); code != "" {
			return []Code{code}
		}
	}
	return nil
}

// expectedFor returns the commitment values the carried manifest declares for
// one attack, or nil when it declares none. An absent expectedPayloads map and
// a map with no entry for this attack are the same answer, which is what the
// requirement asks: a row whose attackId carries no such entry MUST declare
// paired.
func expectedFor(p *Predicate, attackID string) []string {
	if p.Env == nil || p.Env.Corpus == nil || p.Env.Corpus.ExpectedPayloads == nil {
		return nil
	}
	return p.Env.Corpus.ExpectedPayloads[attackID]
}

// pinMatches checks the third part: every interception record the row resolves
// carries in its aeePayloadCommitment at least one value from the manifest's
// entry for the row's attack.
func pinMatches(p *Predicate, row *Row, states []recordState, kinds []string, expected []string) Code {
	want := stringSet(expected)
	for _, idx := range row.Refs {
		if idx < 0 || idx >= len(kinds) || kinds[idx] != KindInterception {
			continue
		}
		obj := payloadObject(&states[idx])
		values, ok := objStringArray(obj, memberPayloadCommitment)
		if !ok {
			// Absent or wrong-typed: the record covers nothing by its own
			// kind's constraints, and that is the fault reported.
			continue
		}
		matched := false
		for _, v := range values {
			if want[v] {
				matched = true
				break
			}
		}
		if !matched {
			return CodeAttributionPinUnmatched
		}
	}
	return ""
}

// commitmentArrayOK is the shared shape rule for aeePayloadCommitment
// (spec:1301-1305): duplicate-free, sorted ascending by UTF-16 code unit,
// non-empty, every entry lowercase 64-hex.
func commitmentArrayOK(values []string) bool {
	if len(values) == 0 || !isSortedNoDuplicates(values) {
		return false
	}
	for _, v := range values {
		if !IsLowerHex64(v) {
			return false
		}
	}
	return true
}
