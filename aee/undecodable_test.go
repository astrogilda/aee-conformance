package aee

import (
	"slices"
	"testing"
)

// TestRecordUndecodableBase64 covers the fail-closed CodeRecordUndecodable
// branch (validity.go checkRecordsStatementLevel + analyzePayload), which had
// no vector exercising it. A record whose payload is not strict RFC 4648
// base64 is rejected before any signature or Merkle check, and the row-level
// analyzePayload short-circuits to the same code rather than parsing garbage.
func TestRecordUndecodableBase64(t *testing.T) {
	// Non-base64 bytes.
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records: []Record{
			{PayloadB64: "@@@not base64@@@", PayloadType: "application/x.aee+json"},
		},
	}
	states, codes := checkRecordsStatementLevel(p)
	if !states[0].decodeErr {
		t.Fatal("expected decodeErr on the undecodable record")
	}
	if !slices.Contains(codes, CodeRecordUndecodable) {
		t.Fatalf("expected CodeRecordUndecodable, got %v", codes)
	}
	if a := analyzePayload(&p.Records[0], &states[0], "binding"); !slices.Contains(a.codes, CodeRecordUndecodable) {
		t.Fatalf("analyzePayload: expected CodeRecordUndecodable, got %v", a.codes)
	}

	// Strict() also rejects non-canonical trailing padding (RFC 4648 sec 3.5):
	// "QUJ=" decodes to "AB" only under lenient decoders, so it must be
	// rejected as undecodable rather than silently accepted.
	p2 := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records:          []Record{{PayloadB64: "QUJ=", PayloadType: "application/x.aee+json"}},
	}
	st2, c2 := checkRecordsStatementLevel(p2)
	if !st2[0].decodeErr || !slices.Contains(c2, CodeRecordUndecodable) {
		t.Fatalf("Strict() must reject non-canonical padding %q; decodeErr=%v codes=%v", "QUJ=", st2[0].decodeErr, c2)
	}
}
