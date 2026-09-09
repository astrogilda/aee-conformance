package corpora

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
)

func init() { register(agentAction{}) }

// agentAction judges vectors-ai-agent-action/. It is the mutation check that
// corpus needs to be worth anything: a vector claiming a chain-hash divergence
// has to actually diverge, and a vector claiming conformance has to actually
// recompute. Without it a generator bug produces a corpus that passes every
// rail and measures nothing.
type agentAction struct{}

func (agentAction) Suite() string { return "ai-agent-action-conformance" }

// canonicalBytesConditions are the conditions whose reject members exist to
// carry NON-canonical bytes. Whether a member must be non-canonical is a
// property of the rule it forces, not of what it is called, so it is read off
// the declared conditions rather than off the identifier's spelling.
var canonicalBytesConditions = map[string]bool{"aia-c-1": true, "aia-c-3": true, "aia-c-4": true}

type agentActionManifest struct {
	PredicateType      string              `json:"predicateType"`
	SpecUpstreamRepo   string              `json:"specUpstreamRepo"`
	SpecUpstreamRef    string              `json:"specUpstreamRef"`
	SpecUpstreamCommit string              `json:"specUpstreamCommit"`
	SpecAuthority      string              `json:"specAuthority"`
	SpecProvenanceNote string              `json:"specProvenanceNote"`
	SpecVendored       string              `json:"specVendored"`
	SpecDigest         string              `json:"specDigest"`
	Counts             map[string]int      `json:"counts"`
	CorpusDigest       string              `json:"corpusDigest"`
	Vectors            []agentActionVector `json:"vectors"`
}

type agentActionVector struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Records    string   `json:"records"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		ChainHash          string  `json:"chainHash"`
		ChainHashCodePoint *string `json:"chainHashCodePoint"`
		ChainHashUtf16     *string `json:"chainHashUtf16"`
		CanonicalNumber    *string `json:"canonicalNumber"`
		IEEE754            *string `json:"ieee754"`
		RequestDigest      *string `json:"requestDigest"`
	} `json:"expected"`
}

func (a agentAction) Judge(dir string, raw []byte) (*Result, error) {
	var m agentActionManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	accepted, rejected := map[string]bool{}, map[string]bool{}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))

	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		for _, c := range v.Conditions {
			switch v.Kind {
			case "accept":
				accepted[c] = true
			case "reject":
				rejected[c] = true
			}
		}
		a.judgeMember(dir, &m, v, &member)
		result.Members = append(result.Members, member)
	}

	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("reject conditions with no accepting twin: %v", orphan))
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the files on disk")
	}
	result.Findings = append(result.Findings, a.checkProvenance(dir, &m)...)
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range m.Vectors {
		if _, k := measured[v.Kind]; k {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	return result, nil
}

func (a agentAction) judgeMember(dir string, m *agentActionManifest, v agentActionVector, out *Member) {
	if !existsIn(dir, v.File) {
		out.Findings = append(out.Findings, "manifest names a file that does not exist")
		return
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	var statement map[string]any
	if err := json.Unmarshal(body, &statement); err != nil {
		out.Findings = append(out.Findings, "the statement does not parse: "+err.Error())
		return
	}
	if predicateType, _ := statement["predicateType"].(string); predicateType != m.PredicateType {
		out.Findings = append(out.Findings, "predicateType does not match the suite")
	}
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, "unknown kind "+v.Kind)
	}

	// The identifier is a digest over the statement's bytes and, where the
	// member has one, its record sidecar joined by a NUL. An edit to either
	// without regenerating leaves a name describing bytes that are no longer
	// there, and this is what lets a corpus-digest failure NAME a member.
	identityPayload := append([]byte{}, body...)

	var lines [][]byte
	if v.Records != "" {
		if !existsIn(dir, v.Records) {
			out.Findings = append(out.Findings, "manifest names a records sidecar that does not exist")
			return
		}
		recordBody, err := readIn(dir, v.Records)
		if err != nil {
			out.Findings = append(out.Findings, err.Error())
			return
		}
		for _, line := range strings.Split(string(recordBody), "\n") {
			if line != "" {
				lines = append(lines, []byte(line))
			}
		}
		identityPayload = append(append(identityPayload, 0x00), recordBody...)
		a.checkChainMembers(v, lines, out)
		if v.Expected.ChainHash != "" && len(lines) > 0 {
			last := lines[len(lines)-1]
			if v.Kind == "accept" && sha(last) != v.Expected.ChainHash {
				out.Findings = append(out.Findings,
					"declared chainHash does not recompute from the last record line")
			}
			if v.Kind == "reject" && sha(last) == v.Expected.ChainHash {
				out.Findings = append(out.Findings,
					"a reject member's subject digest recomputes cleanly, so nothing is being caught")
			}
		}
	}

	if idFromBytes(identityPayload) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}

	predicate, _ := statement["predicate"].(map[string]any)
	extensions := predicate["extensions"]
	switch v.ID {
	case "ok-010-extensions-depth-128":
		if measured := jsonDepth(extensions, 1); measured != 128 {
			out.Findings = append(out.Findings, fmt.Sprintf("claims depth 128, measured %d", measured))
		}
	case "bad-114-extensions-depth-129":
		if measured := jsonDepth(extensions, 1); measured != 129 {
			out.Findings = append(out.Findings, fmt.Sprintf("claims depth 129, measured %d", measured))
		}
	case "bad-115-unsafe-integer-durationms":
		a.checkUnsafeInteger(body, out)
	case "ok-013-bmp-extension-member-names", "bad-116-astral-extension-member-name":
		a.checkMemberNameOrders(v, predicate, lines, out)
	}
	a.checkAppendixB(v, predicate, out)
}

// checkUnsafeInteger reads durationMs off the raw statement bytes rather than
// off a parsed float64: the value under test is outside the range a float64
// represents exactly, and parsing it into one is how the member stops being
// unsafe on the way in.
func (agentAction) checkUnsafeInteger(body []byte, out *Member) {
	value, ok := rawNumberAt(body, "predicate", "action", "durationMs")
	if !ok {
		out.Findings = append(out.Findings, "carries no predicate.action.durationMs to measure")
		return
	}
	magnitude := strings.TrimPrefix(value.String(), "-")
	if n, err := strconv.ParseInt(magnitude, 10, 64); err == nil && n < 1<<53 {
		out.Findings = append(out.Findings, "claims an unsafe integer and carries a safe one")
	}
}

func rawNumberAt(body []byte, keys ...string) (json.Number, bool) {
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return "", false
	}
	for _, key := range keys {
		object, ok := value.(map[string]any)
		if !ok {
			return "", false
		}
		value = object[key]
	}
	number, ok := value.(json.Number)
	return number, ok
}

// jsonDepth is the corpus's own depth: a scalar sits at level-1, so an empty
// object is depth 1 and a scalar reached through one object is depth 1 too.
func jsonDepth(node any, level int) int {
	deepest := level
	switch v := node.(type) {
	case map[string]any:
		for _, child := range v {
			if d := jsonDepth(child, level+1); d > deepest {
				deepest = d
			}
		}
	case []any:
		for _, child := range v {
			if d := jsonDepth(child, level+1); d > deepest {
				deepest = d
			}
		}
	default:
		return level - 1
	}
	return deepest
}

// checkChainMembers asserts each line is, or is not, its own canonical form.
func (agentAction) checkChainMembers(v agentActionVector, lines [][]byte, out *Member) {
	allCanonical := true
	for _, line := range lines {
		canonical := false
		if hasUnpairedSurrogateEscape(line) {
			// The line carries an unpaired surrogate, so it has no UTF-8
			// encoding at all and cannot be canonical.
			if v.Kind == "accept" {
				out.Findings = append(out.Findings, "an accept member carries an unencodable string")
			}
		} else if value, err := decodeJSONNumbers(line); err == nil {
			if encoded, err := pythonCompactJSONOpts(value, pyEncodeOpts{}); err == nil {
				canonical = sha(encoded) == sha(line)
			}
		}
		if !canonical {
			allCanonical = false
		}
	}
	if v.Kind == "accept" && !allCanonical {
		out.Findings = append(out.Findings, "an accept member carries a non-canonical log line")
	}
	if v.Kind != "reject" || allCanonical == false {
		return
	}
	for _, condition := range v.Conditions {
		if canonicalBytesConditions[condition] {
			out.Findings = append(out.Findings,
				"a canonicalization reject member is already canonical, so it demonstrates nothing")
			return
		}
	}
}

// hasUnpairedSurrogateEscape finds a \uD800-\uDFFF escape that is not half of a
// well-formed pair. Go's JSON decoder silently replaces one with U+FFFD, so a
// reader that decoded first could not tell this member from a valid one, and
// that member is the whole point of one vector.
func hasUnpairedSurrogateEscape(line []byte) bool {
	s := string(line)
	for i := 0; i+6 <= len(s); i++ {
		if s[i] != '\\' || s[i+1] != 'u' {
			continue
		}
		value, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
		if err != nil {
			continue
		}
		switch {
		case value >= 0xd800 && value <= 0xdbff:
			if i+12 > len(s) || s[i+6] != '\\' || s[i+7] != 'u' {
				return true
			}
			low, err := strconv.ParseUint(s[i+8:i+12], 16, 32)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 11
		case value >= 0xdc00 && value <= 0xdfff:
			return true
		}
	}
	return false
}

// checkMemberNameOrders recomputes the ok-013 / bad-116 pair rather than taking
// it on trust. An accept member must carry only BMP member names and the two
// sort orders must agree on them; a reject member must carry a
// supplementary-plane member name and the two orders must actually disagree. A
// pair whose orders happened to coincide would prove nothing while reading
// exactly the same.
func (agentAction) checkMemberNameOrders(v agentActionVector, predicate map[string]any, lines [][]byte, out *Member) {
	extensions, ok := predicate["extensions"].(map[string]any)
	if !ok || len(extensions) == 0 {
		out.Findings = append(out.Findings, "carries no extensions object, so there are no member names to sort")
		return
	}
	var names, astral []string
	for name := range extensions {
		names = append(names, name)
		for _, r := range name {
			if r > 0xffff {
				astral = append(astral, name)
				break
			}
		}
	}
	byCodePoint, byUTF16 := sortedStrings(names), sortedStrings(names)
	sortByUTF16(byUTF16)
	diverges := strings.Join(byCodePoint, "\x00") != strings.Join(byUTF16, "\x00")

	if v.Kind == "accept" && len(astral) > 0 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"an accept member carries a supplementary-plane member name %v", sortedStrings(astral)))
	}
	if v.Kind == "reject" && len(astral) == 0 {
		out.Findings = append(out.Findings, "claims a supplementary-plane member name and carries none")
	}
	if v.Kind == "accept" && diverges {
		out.Findings = append(out.Findings,
			"the two sort orders disagree on an accept member, so it is not the admissible "+
				"side of the boundary")
	}
	if v.Kind == "reject" && !diverges {
		out.Findings = append(out.Findings,
			"code-point order and UTF-16 code-unit order agree on these member names, so the "+
				"member demonstrates no divergence")
	}
	if len(lines) == 0 {
		out.Findings = append(out.Findings,
			"declares ordering digests with no record sidecar to recompute them from")
		return
	}
	last := lines[len(lines)-1]
	record, err := decodeJSONNumbers(last)
	if err != nil {
		out.Findings = append(out.Findings, "the sidecar record does not parse: "+err.Error())
		return
	}
	codePointForm, err1 := pythonCompactJSONOpts(record, pyEncodeOpts{})
	utf16Form, err2 := pythonCompactJSONOpts(record, pyEncodeOpts{UTF16Order: true})
	if err1 != nil || err2 != nil {
		out.Findings = append(out.Findings, "the sidecar record does not re-encode")
		return
	}
	for _, pair := range []struct {
		key      string
		declared *string
		form     []byte
	}{
		{"chainHashCodePoint", v.Expected.ChainHashCodePoint, codePointForm},
		{"chainHashUtf16", v.Expected.ChainHashUtf16, utf16Form},
	} {
		if pair.declared == nil {
			out.Findings = append(out.Findings, "declares no "+pair.key)
			continue
		}
		if *pair.declared != sha(pair.form) {
			out.Findings = append(out.Findings, pair.key+" does not recompute from the sidecar record")
		}
	}
	// The sidecar must carry the bytes RFC 8785 requires, which is the
	// UTF-16-code-unit ordering. Recomputing the digests above cannot see this,
	// because parsing discards member order.
	if string(last) != string(utf16Form) {
		out.Findings = append(out.Findings,
			"the sidecar line is not the RFC 8785 canonical bytes, which are sorted by "+
				"UTF-16 code unit")
	}
	if diverges && string(last) == string(codePointForm) {
		out.Findings = append(out.Findings,
			"the sidecar line is in code-point order, so the corpus ships the divergent "+
				"reading as though it were canonical")
	}
	same := v.Expected.ChainHashUtf16 != nil && v.Expected.ChainHashCodePoint != nil &&
		*v.Expected.ChainHashUtf16 == *v.Expected.ChainHashCodePoint
	if diverges && same {
		out.Findings = append(out.Findings,
			"declares one chain hash for a record whose two orderings produce different bytes")
	}
	if !diverges && !same {
		out.Findings = append(out.Findings,
			"declares two chain hashes for a record whose two orderings produce identical bytes")
	}
}

func sortByUTF16(names []string) {
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && utf16Less(names[j], names[j-1]); j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
}

// checkAppendixB checks an Appendix B row without reusing the generator's
// serializer. Recomputing the canonical bytes with the same function that wrote
// them would only prove the generator agrees with itself, so neither step below
// calls it: the declared text is parsed back to a double, and the digest is
// taken over the declared text directly.
func (agentAction) checkAppendixB(v agentActionVector, predicate map[string]any, out *Member) {
	if !strings.Contains(v.ID, "appendix-b") {
		return
	}
	if v.Expected.CanonicalNumber == nil || v.Expected.IEEE754 == nil || v.Expected.RequestDigest == nil {
		out.Findings = append(out.Findings,
			"is an Appendix B row and declares no canonicalNumber, ieee754 or requestDigest")
		return
	}
	want, hexPattern, declared := *v.Expected.CanonicalNumber, *v.Expected.IEEE754, *v.Expected.RequestDigest
	parsed, err := strconv.ParseFloat(want, 64)
	if err != nil {
		out.Findings = append(out.Findings, fmt.Sprintf("canonicalNumber %q does not parse as a double", want))
		return
	}
	// Both zeros print as "0", which is the lossy step Appendix B row 2 exists
	// to pin, so either zero pattern satisfies the zero text and nothing else does.
	if parsed == 0 {
		if hexPattern != "0000000000000000" && hexPattern != "8000000000000000" {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"canonicalNumber %q is zero and ieee754 %s is not a zero pattern", want, hexPattern))
		}
	} else {
		var packed [8]byte
		binary.BigEndian.PutUint64(packed[:], math.Float64bits(parsed))
		if actual := fmt.Sprintf("%x", packed); actual != hexPattern {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"canonicalNumber %q parses to %s, not the declared %s", want, actual, hexPattern))
		}
	}
	canonical := []byte(`{"value":` + want + "}")
	if sha(canonical) != declared {
		out.Findings = append(out.Findings, fmt.Sprintf("requestDigest is not the digest of %q", canonical))
	}
	carried := ""
	if contentDigest, ok := predicate["contentDigest"].(map[string]any); ok {
		if request, ok := contentDigest["request"].(map[string]any); ok {
			carried, _ = request["sha256"].(string)
		}
	}
	if carried != declared {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"the statement carries request digest %s and the manifest declares %s",
			short(carried), short(declared)))
	}
}

// checkProvenance asserts the manifest says where the vendored text came from
// and which pin is load-bearing. The commit is orphaned upstream, so a pin on
// it is a pin on nothing; the digest is the only one this suite can enforce.
func (agentAction) checkProvenance(dir string, m *agentActionManifest) []string {
	var findings []string
	for _, field := range []struct{ name, value string }{
		{"specUpstreamRepo", m.SpecUpstreamRepo},
		{"specUpstreamRef", m.SpecUpstreamRef},
		{"specAuthority", m.SpecAuthority},
		{"specProvenanceNote", m.SpecProvenanceNote},
	} {
		if field.value == "" {
			findings = append(findings, "the manifest carries no "+field.name+
				", so it does not say where the vendored text came from or which pin is load-bearing")
		}
	}
	if m.SpecAuthority != "specDigest" {
		findings = append(findings,
			"specAuthority names something other than specDigest. The commit is orphaned "+
				"upstream, so a pin on it is a pin on nothing; the digest is the only one this "+
				"suite can enforce.")
	}
	stem := strings.TrimSuffix(path.Base(m.SpecVendored), path.Ext(m.SpecVendored))
	if len(m.SpecUpstreamCommit) >= 7 {
		if shortSha := m.SpecUpstreamCommit[:7]; !strings.HasSuffix(stem, shortSha) {
			findings = append(findings, fmt.Sprintf(
				"the vendored copy is named %q while the manifest pins commit %s, so the file "+
					"name and the pin disagree about which revision is on disk", stem, shortSha))
		}
	}
	if bad := checkVendored(dir, m.SpecVendored, m.SpecDigest, "specification"); bad != "" {
		findings = append(findings, bad)
	}
	return findings
}
