package aee_test

import (
	"encoding/json"
	"testing"

	"github.com/astrogilda/aee-conformance/aee"
	"github.com/astrogilda/aee-conformance/aeetest"
)

// mutateRecordSignatures rebuilds a built statement with a mutation applied to
// the signatures member of every observation record at an index in targets.
// Returning nil for the replacement value deletes the member outright, which
// is how the "no signatures member at all" case is expressed.
func mutateRecordSignatures(t *testing.T, raw []byte, targets []int, replacement any) []byte {
	t.Helper()
	var stmt map[string]any
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("built statement does not parse: %v", err)
	}
	predicate, ok := stmt["predicate"].(map[string]any)
	if !ok {
		t.Fatal("built statement carries no predicate object")
	}
	records, ok := predicate["observationRecords"].([]any)
	if !ok {
		t.Fatal("built statement carries no observationRecords array")
	}
	for _, idx := range targets {
		record, ok := records[idx].(map[string]any)
		if !ok {
			t.Fatalf("observationRecords[%d] is not an object", idx)
		}
		if replacement == nil {
			delete(record, "signatures")
			continue
		}
		record["signatures"] = replacement
	}
	out, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return out
}

func batchRootOf(t *testing.T, raw []byte) string {
	t.Helper()
	var stmt struct {
		Predicate struct {
			BatchRoot string `json:"batchRoot"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		t.Fatalf("statement does not parse: %v", err)
	}
	return stmt.Predicate.BatchRoot
}

// TestRecordSignaturesEmptyIsInvalid covers the spec requirement that a
// record's signatures member carry at least one entry. Both spellings of zero
// entries -- an empty array and no member at all -- are the same fault.
func TestRecordSignaturesEmptyIsInvalid(t *testing.T) {
	cases := []struct {
		name        string
		replacement any
	}{
		{"empty array", []any{}},
		{"member absent", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mutateRecordSignatures(t, aeetest.Build(aeetest.Options{}), []int{0}, tc.replacement)
			requireInvalid(t, aee.Verify(b, pinnedPolicy()), aee.CodeRecordSignaturesEmpty)
		})
	}
}

// TestRecordSignaturesEmptyOnOneOfManyRecords pins that the check is per
// record, not "some record somewhere is signed": a clean row is covered by an
// arming record and a sealed record, and stripping either one's signatures is
// enough to reject the statement.
func TestRecordSignaturesEmptyOnOneOfManyRecords(t *testing.T) {
	for _, idx := range []int{0, 1} {
		b := mutateRecordSignatures(t, aeetest.Build(aeetest.Options{Clean: true}), []int{idx}, []any{})
		requireInvalid(t, aee.Verify(b, pinnedPolicy()), aee.CodeRecordSignaturesEmpty)
	}
}

// TestSignaturesInvisibleToBatchRoot is the empirical basis for putting the
// count in the byte-pure layer at all. A DSSE leaf is H(0x00 || PAE) and the
// PAE pre-image spans only payloadType and payload, so signatures are outside
// every committed digest: stripping all of them leaves batchRoot bit for bit
// identical. Nothing already in the layer could notice, which is why a
// consumer gating on result alone admitted an entirely unsigned attestation.
func TestSignaturesInvisibleToBatchRoot(t *testing.T) {
	signed := aeetest.Build(aeetest.Options{Clean: true})
	stripped := mutateRecordSignatures(t, signed, []int{0, 1}, []any{})

	if got, want := batchRootOf(t, stripped), batchRootOf(t, signed); got != want {
		t.Fatalf("batchRoot moved when signatures were stripped: %s != %s", got, want)
	}
	requireInvalid(t, aee.Verify(stripped, pinnedPolicy()), aee.CodeRecordSignaturesEmpty)
}

// TestPresentSignaturesArePassedNotVerified states the check's ceiling in a
// test rather than only in a comment. A single entry carrying garbage
// signature bytes satisfies the count, so the statement stays VALID at the
// byte-pure layer; the fabrication is caught one gate later, where the row
// derives unattested instead of attested. The check converts "admits zero
// signatures" into "admits structurally-present, unchecked signatures", and
// nothing more.
func TestPresentSignaturesArePassedNotVerified(t *testing.T) {
	garbage := []any{map[string]any{"keyid": "", "sig": "bm90LWEtc2lnbmF0dXJl"}}
	b := mutateRecordSignatures(t, aeetest.Build(aeetest.Options{}), []int{0}, garbage)

	r := aee.Verify(b, pinnedPolicy())
	requireValid(t, r)
	if len(r.Tiers) != 1 || r.Tiers[0] != aee.TierUnattested {
		t.Fatalf("fabricated signature must derive unattested, got %v", r.Tiers)
	}
	if r.Admitted {
		t.Fatal("a statement with unverifiable signatures must not be admitted")
	}
}
