package aee

import (
	"encoding/base64"
	"slices"
	"testing"
)

// The duplicate scan and the batch-root check used to share one guard, so a
// single record that failed base64 suppressed both. This file pins the split.
//
// Skipping the ROOT on a decode failure is correct and stays: an undecodable
// record leaves the zero value in the leaf array, so the root would be computed
// over a leaf that does not exist. Skipping the DUPLICATE scan is not, because
// the records that decoded still carry whatever duplicate they carried, and this
// contract is compared as a SET OF CODES -- so a statement holding both a
// duplicate and an undecodable record reported `record-undecodable` and dropped
// `duplicate-record` entirely.
//
// No vector in the corpus paired those two conditions, which is why nothing
// caught it. One does now: bad-410-duplicate-and-undecodable-record, replayed
// against this rail by TestSetEmissionOnPairedRecordFaults in vectors_test.go.
// The tests here work on the record-set check directly and that one works on
// the vector's committed bytes, which is the difference between pinning the
// split and pinning it over the artifact a third party downloads.

const dupTestType = "application/x.aee+json"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestDuplicateIsFoundEvenWhenAnotherRecordIsUndecodable is the regression: the
// duplicate must be reported ALONGSIDE the decode failure, not instead of it.
func TestDuplicateIsFoundEvenWhenAnotherRecordIsUndecodable(t *testing.T) {
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records: []Record{
			{PayloadB64: b64(`{"a":1}`), PayloadType: dupTestType},
			{PayloadB64: b64(`{"a":1}`), PayloadType: dupTestType}, // the duplicate
			{PayloadB64: "@@@not base64@@@", PayloadType: dupTestType},
		},
	}
	_, codes := checkRecordsStatementLevel(p)
	if !slices.Contains(codes, CodeRecordUndecodable) {
		t.Fatalf("expected %v, got %v", CodeRecordUndecodable, codes)
	}
	if !slices.Contains(codes, CodeDuplicateRecord) {
		t.Fatalf("the undecodable record masked the duplicate: expected %v in %v",
			CodeDuplicateRecord, codes)
	}
}

// TestTwoUndecodableRecordsAreNotADuplicate is the trap the original guard was
// avoiding, and the reason the fix skips non-decoding entries rather than
// scanning the leaf array wholesale. Two undecodable records both hold the zero
// leaf; reporting that as a duplicate would be a finding about the loop rather
// than about the statement.
func TestTwoUndecodableRecordsAreNotADuplicate(t *testing.T) {
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records: []Record{
			{PayloadB64: "@@@one@@@", PayloadType: dupTestType},
			{PayloadB64: "@@@two@@@", PayloadType: dupTestType},
		},
	}
	_, codes := checkRecordsStatementLevel(p)
	if !slices.Contains(codes, CodeRecordUndecodable) {
		t.Fatalf("expected %v, got %v", CodeRecordUndecodable, codes)
	}
	if slices.Contains(codes, CodeDuplicateRecord) {
		t.Fatalf("two undecodable records were reported as duplicates of each other: %v", codes)
	}
}

// TestDecodeFailureStillSuppressesTheRootCheck pins the half that was right, so
// a later change cannot quietly start computing a root over a leaf that was
// never produced.
func TestDecodeFailureStillSuppressesTheRootCheck(t *testing.T) {
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		BatchRoot:        "00", // deliberately wrong, and must NOT be reported
		Records: []Record{
			{PayloadB64: b64(`{"a":1}`), PayloadType: dupTestType},
			{PayloadB64: "@@@not base64@@@", PayloadType: dupTestType},
		},
	}
	_, codes := checkRecordsStatementLevel(p)
	if slices.Contains(codes, CodeBatchRootMismatch) {
		t.Fatalf("the root was compared against a leaf set containing a hole: %v", codes)
	}
}

// TestDuplicateStillFoundWhenEverythingDecodes is the control: without it, a fix
// that broke the ordinary path would still pass the three tests above.
func TestDuplicateStillFoundWhenEverythingDecodes(t *testing.T) {
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records: []Record{
			{PayloadB64: b64(`{"a":1}`), PayloadType: dupTestType},
			{PayloadB64: b64(`{"a":1}`), PayloadType: dupTestType},
		},
	}
	_, codes := checkRecordsStatementLevel(p)
	if !slices.Contains(codes, CodeDuplicateRecord) {
		t.Fatalf("expected %v, got %v", CodeDuplicateRecord, codes)
	}
}
