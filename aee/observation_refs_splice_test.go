package aee_test

// Cross-row observationRefs splice: exchanging the record ASSIGNMENT between
// two rows while leaving the record SET untouched.
//
// Every other mutation in this suite moves a byte some gate reads. This one
// moves the one field that binds a row to its evidence, and no gate reads the
// binding: L664-671 of the predicate states the rule as a producer obligation
// ("A producer MUST NOT reference a record from a row whose attack the
// record's committed payload does not evidence") and then states, in the same
// sentence, that no validity requirement, recompute input or tier evaluation
// reads it, so a conforming verifier "neither can nor may invent an evidencing
// heuristic for shared references". L913 spells out the consequence: no record
// names its attack, because a substrate signs at observation time and before
// attribution.
//
// The measurement below is therefore an expected NULL, and it is pinned rather
// than assumed for two reasons. A null result nothing asserts is
// indistinguishable from a check that was never run; and the null is the exact
// claim a future revision would falsify, so a rail that starts authenticating
// the assignment turns this file red and brings whoever wrote that rule here to
// say so, instead of leaving the record stale.
//
// What makes the null trustworthy is TestCaughtToCleanSpliceIsRejected, the
// positive control. It applies the SAME operator to a different row pair and
// the rail kills it. The two together locate the boundary precisely: the rail
// authenticates a row's coverage CLASS -- that a caught row resolves some
// interception, that a clean row resolves an arming and a sealed record -- and
// never the ASSIGNMENT within a class. A consumer policy that discriminates
// between attacks by severity, class, regulatory mapping or attack identifier
// is reading a mapping the producer may permute at will, with every signature,
// count, root and validity rule still satisfied.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/astrogilda/aee-conformance/aee"
	"github.com/astrogilda/aee-conformance/aeetest"
)

// Synthetic pre-images, each a committed one-liner, mirroring aeetest's
// discipline: every digest is DERIVED here, never typed in.
func spliceDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return aee.SHA256Hex(canon)
}

// spliceEnv is everything a statement carries that both bases share.
type spliceEnv struct {
	env      map[string]any
	binding  string
	manifest map[string]any
}

func newSpliceEnv(t *testing.T, manifest map[string]any) spliceEnv {
	t.Helper()
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	vocabDigest := spliceDigest(t, map[string]any{"caught": caught, "labels": labels})
	corpusDigest := spliceDigest(t, manifest)

	catchPolicyDigest := spliceDigest(t, map[string]any{"examplePolicy": "enforcing"})
	postureDigest := spliceDigest(t, map[string]any{"examplePosture": "sinkhole"})
	substrateDigest := spliceDigest(t, map[string]any{"exampleSubstrate": "image"})
	subjectDigest := spliceDigest(t, map[string]any{"exampleSubject": "bundle"})
	runEntropyDigest := aee.SHA256Hex([]byte("example-run-start-checkpoint/1"))

	posture := map[string]any{
		"digest":  map[string]any{"sha256": postureDigest},
		"posture": "sinkhole",
	}
	binding := aee.DeriveRunBinding(
		catchPolicyDigest, corpusDigest, spliceDigest(t, posture),
		vocabDigest, runEntropyDigest, subjectDigest, substrateDigest,
	)

	env := map[string]any{
		"catchPolicy": map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
		"corpus": map[string]any{
			"digest":   map[string]any{"sha256": corpusDigest},
			"manifest": manifest,
			"name":     "example-corpus",
			"uri":      "pkg:example/corpus@1",
		},
		"networkPosture": posture,
		"observationVocabulary": map[string]any{
			"caught": caught,
			"digest": map[string]any{"sha256": vocabDigest},
			"labels": labels,
		},
		"runEntropy": map[string]any{"digest": map[string]any{"sha256": runEntropyDigest}},
		"substrate": map[string]any{
			"digest": map[string]any{"sha256": substrateDigest},
			"name":   "example-substrate",
		},
	}
	return spliceEnv{env: env, binding: binding, manifest: manifest}
}

func (e spliceEnv) subjectDigest(t *testing.T) string {
	t.Helper()
	return spliceDigest(t, map[string]any{"exampleSubject": "bundle"})
}

func (e spliceEnv) postureDigest(t *testing.T) string {
	t.Helper()
	return spliceDigest(t, map[string]any{"examplePosture": "sinkhole"})
}

// signSpliceRecord signs one record payload under the pinned substrate key.
func signSpliceRecord(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize record: %v", err)
	}
	signer := aeetest.TestKey(aeetest.RoleSubstrateObservation)
	sig := ed25519.Sign(signer, aee.PAE(aeetest.PayloadType, canon))
	return map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(canon),
		"payloadType": aeetest.PayloadType,
		"signatures": []any{map[string]any{
			"keyid": aeetest.KeyID(signer.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
}

func spliceBatchRoot(t *testing.T, records []map[string]any) string {
	t.Helper()
	leaves := make([][32]byte, len(records))
	for i, rec := range records {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
	}
	root := aee.MerkleRoot(leaves)
	return fmt.Sprintf("%x", root[:])
}

// assemble canonicalizes a whole statement around the supplied rows and records.
func (e spliceEnv) assemble(t *testing.T, rows []any, records []map[string]any, assessed []any) []byte {
	t.Helper()
	recs := make([]any, len(records))
	for i, r := range records {
		recs[i] = r
	}
	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": aee.PredicateType,
		"subject": []any{map[string]any{
			"digest": map[string]any{"sha256": e.subjectDigest(t)},
			"name":   "example-agent-bundle",
		}},
		"predicate": map[string]any{
			"attackResults": rows,
			"batchRoot":     spliceBatchRoot(t, records),
			"coverage": map[string]any{
				"assessedClasses": assessed,
				"outOfScope":      map[string]any{},
				"routedElsewhere": map[string]any{},
			},
			"issuedAt":               aeetest.IssuedAt,
			"observationEnvironment": e.env,
			"observationRecords":     recs,
			"result":                 "fail",
		},
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize statement: %v", err)
	}
	return canon
}

func caughtRow(attackID string, refs []any) map[string]any {
	return map[string]any{
		"actualLayer":         "policy.egress_sinkhole",
		"attackId":            attackID,
		"basis":               "substrate",
		"containmentObserved": "egress_captured",
		"method":              "intercepted",
		"observationRefs":     refs,
	}
}

func cleanRow(attackID string, refs []any) map[string]any {
	return map[string]any{
		"actualLayer":         "none",
		"attackId":            attackID,
		"basis":               "substrate",
		"containmentObserved": "no_egress",
		"method":              "intercepted",
		"observationRefs":     refs,
	}
}

// twoCaughtRows builds a statement whose two rows are IDENTICAL in every member
// a gate reads except attackId and observationRefs, each resolving its own
// interception record, and whose attacks sit in different corpus classes. The
// class split is deliberate: a consumer policy keyed on attack class is the
// cheapest example of one that reads the assignment.
func twoCaughtRows(t *testing.T) ([]byte, spliceEnv) {
	t.Helper()
	e := newSpliceEnv(t, map[string]any{"classes": map[string]any{
		"XA": []any{"XA-EXAMPLE-1"},
		"XB": []any{"XB-EXAMPLE-1"},
	}})
	interception := func(note string) map[string]any {
		return signSpliceRecord(t, map[string]any{
			"aeeKind":       "interception",
			"aeeMethod":     "intercepted",
			"aeeRunBinding": e.binding,
			"producerNote":  note,
		})
	}
	records := []map[string]any{
		interception("example interception commitment A"),
		interception("example interception commitment B"),
	}
	rows := []any{
		caughtRow("XA-EXAMPLE-1", []any{0}),
		caughtRow("XB-EXAMPLE-1", []any{1}),
	}
	return e.assemble(t, rows, records, []any{"XA", "XB"}), e
}

// caughtAndCleanRows builds the control base: one caught row resolving an
// interception, one clean row resolving the arming and sealed pair. The two
// rows sit in DIFFERENT coverage classes, which is the only thing that
// separates this base from the one above.
func caughtAndCleanRows(t *testing.T) []byte {
	t.Helper()
	e := newSpliceEnv(t, map[string]any{"classes": map[string]any{
		"XA": []any{"XA-EXAMPLE-1", "XA-EXAMPLE-2"},
	}})
	records := []map[string]any{
		signSpliceRecord(t, map[string]any{
			"aeeKind":       "interception",
			"aeeMethod":     "intercepted",
			"aeeRunBinding": e.binding,
			"producerNote":  "example interception commitment",
		}),
		signSpliceRecord(t, map[string]any{
			"aeeKind":          "arming",
			"aeeMethod":        "intercepted",
			"aeePostureDigest": e.postureDigest(t),
			"aeeRunBinding":    e.binding,
			"armedAt":          aeetest.ArmedAt,
			"producerNote":     "example arming record",
		}),
		signSpliceRecord(t, map[string]any{
			"aeeDropCount":     0,
			"aeeKind":          "sealed",
			"aeeMethod":        "intercepted",
			"aeePostureDigest": e.postureDigest(t),
			"aeeRunBinding":    e.binding,
			"aeeStillArmed":    true,
		}),
	}
	rows := []any{
		caughtRow("XA-EXAMPLE-1", []any{0}),
		cleanRow("XA-EXAMPLE-2", []any{1, 2}),
	}
	return e.assemble(t, rows, records, []any{"XA"})
}

// splice exchanges observationRefs between two rows and canonicalizes the
// result. Nothing else in the statement is touched, so the record set, every
// signature, every digest and the batch root are the producer's own bytes.
func splice(t *testing.T, body []byte, i, j int) []byte {
	t.Helper()
	var stmt map[string]any
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	rows := stmt["predicate"].(map[string]any)["attackResults"].([]any)
	ri := rows[i].(map[string]any)
	rj := rows[j].(map[string]any)
	ri["observationRefs"], rj["observationRefs"] = rj["observationRefs"], ri["observationRefs"]
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize spliced statement: %v", err)
	}
	return canon
}

// refsOf reports each row's observationRefs, rendered, in row order.
func refsOf(t *testing.T, body []byte) []string {
	t.Helper()
	var stmt map[string]any
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	rows := stmt["predicate"].(map[string]any)["attackResults"].([]any)
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = fmt.Sprint(r.(map[string]any)["observationRefs"])
	}
	return out
}

// fingerprint renders a whole report, so the comparison below cannot pass by
// omitting a field that a later revision adds.
func fingerprint(t *testing.T, r *aee.Report) string {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// requireSpliceMoved asserts the mutation altered the bytes it claims to and
// only those: the statement differs, the per-row refs differ, and the MULTISET
// of refs across all rows is unchanged, which is what makes it an assignment
// permutation rather than an edit to the reference set.
func requireSpliceMoved(t *testing.T, base, mutated []byte, i, j int) {
	t.Helper()
	if string(base) == string(mutated) {
		t.Fatal("splice changed no bytes; the mutation asserts nothing")
	}
	before, after := refsOf(t, base), refsOf(t, mutated)
	if before[i] == after[i] || before[j] == after[j] {
		t.Fatalf("rows %d/%d refs did not move: %v -> %v", i, j, before, after)
	}
	if before[i] != after[j] || before[j] != after[i] {
		t.Fatalf("refs were not exchanged: %v -> %v", before, after)
	}
	for k := range before {
		if k != i && k != j && before[k] != after[k] {
			t.Fatalf("row %d refs changed and should not have: %v -> %v", k, before, after)
		}
	}
}

// TestCrossRowObservationRefsSpliceIsInvisible is the measurement. Exchanging
// the record assignment between two rows of the same coverage class leaves the
// rail's whole report byte-identical, under a pinned key policy and under none.
//
// This is not a rule passing. It is the absence of a rule, recorded where it
// can be re-measured: the corpus cell U7 in vectors/coverage-unforced.json
// carries the same finding in the published matrix.
func TestCrossRowObservationRefsSpliceIsInvisible(t *testing.T) {
	base, _ := twoCaughtRows(t)
	mutated := splice(t, base, 0, 1)
	requireSpliceMoved(t, base, mutated, 0, 1)

	policies := map[string]*aee.ConsumerPolicy{
		"pinned key": pinnedPolicy(),
		"no key":     nil,
	}
	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			before := aee.Verify(base, policy)
			requireValid(t, before)
			after := aee.Verify(mutated, policy)
			got, want := fingerprint(t, after), fingerprint(t, before)
			if got != want {
				t.Fatalf("the rail distinguishes the splice:\n before %s\n after  %s", want, got)
			}
			if before.Result != "fail" {
				t.Fatalf("base result %q, want fail", before.Result)
			}
		})
	}
}

// TestCaughtToCleanSpliceIsRejected is the positive control for the test above.
// Same operator, same statement shape, rows drawn from DIFFERENT coverage
// classes: the rail kills it. Without this case, a splice the rail cannot see
// and a harness that cannot see any splice produce the same green run.
func TestCaughtToCleanSpliceIsRejected(t *testing.T) {
	base := caughtAndCleanRows(t)
	requireValid(t, aee.Verify(base, pinnedPolicy()))

	mutated := splice(t, base, 0, 1)
	requireSpliceMoved(t, base, mutated, 0, 1)

	r := aee.Verify(mutated, pinnedPolicy())
	requireInvalid(t, r, aee.CodeCaughtRowUncovered)
}
