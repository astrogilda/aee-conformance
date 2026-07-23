package aee

// Tests for the BMP-only string profile: the vocabulary-entry rejection at
// GATE 0, the covering-payload member-name rejection at the payload analysis,
// and the UTF-16 code-unit comparator pin the profile rests on.

import (
	"strings"
	"testing"
)

// TestUTF16ComparatorOrdersSupplementaryBeforePrivateUse pins the sort
// predicate used for observationVocabulary.labels/caught (and for member
// names) to UTF-16 code-unit order: a supplementary-plane string, whose
// first UTF-16 unit is a lead surrogate in 0xD800..0xDBFF, orders BEFORE a
// BMP private-use code point in 0xE000..0xF8FF, while Unicode code-point
// order places it after. With the BMP-only profile enforced, no corpus
// vector can probe this divergence: every accepted vocabulary is BMP-only,
// and within the BMP the two orders coincide. This unit test is therefore
// deliberately the regression pin at the only layer where the comparator's
// order is still expressible; reverting the comparator to code-point
// ordering turns it red.
func TestUTF16ComparatorOrdersSupplementaryBeforePrivateUse(t *testing.T) {
	private := "\uE000"           // BMP private-use: single UTF-16 unit 0xE000
	supplementary := "\U0001F600" // U+1F600: UTF-16 units 0xD83D 0xDE00

	if !utf16Less(supplementary, private) {
		t.Fatalf("utf16Less(%q, %q) = false; UTF-16 code-unit order requires the lead surrogate 0xD83D to sort before 0xE000", supplementary, private)
	}
	if utf16Less(private, supplementary) {
		t.Fatalf("utf16Less(%q, %q) = true; under code-unit order the private-use string sorts after the supplementary-plane string", private, supplementary)
	}
	// Control: the code points compare the other way round, so a comparator
	// reverted to code-point order fails the assertions above.
	if rune(0xE000) >= rune(0x1F600) {
		t.Fatal("control: expected U+E000 < U+1F600 by code point")
	}
}

func TestIsBMPOnly(t *testing.T) {
	for _, ok := range []string{"", "ascii", "caf\u00e9", "\u20ac", "\uE000", "\uFFFF"} {
		if !isBMPOnly(ok) {
			t.Errorf("isBMPOnly(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"\U0001F600", "a\U00010000b", "\U0010FFFF"} {
		if isBMPOnly(bad) {
			t.Errorf("isBMPOnly(%q) = true, want false", bad)
		}
	}
}

func TestHasSupplementaryMemberNameWalksNestedObjects(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`{"a":1}`, false},
		{`{"a":{"b":[{"c":"😀"}]}}`, false}, // non-BMP VALUE is fine
		{`{"zz😀":1}`, true},
		{`{"a":{"zz😀":1}}`, true},
		{`{"a":[{"zz😀":1}]}`, true},
	}
	for _, tc := range cases {
		v, err := parseJSONValue([]byte(tc.raw))
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if got := hasSupplementaryMemberName(v); got != tc.want {
			t.Errorf("hasSupplementaryMemberName(%s) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// vocabWithDigest builds a Vocabulary whose digest matches its content, so
// the BMP rejection under test is the only violation.
func vocabWithDigest(labels, caught []string) *Vocabulary {
	return &Vocabulary{
		Labels:        labels,
		Caught:        caught,
		LabelsPresent: true,
		CaughtPresent: true,
		Digest:        map[string]string{"sha256": SHA256Hex(canonicalVocabulary(labels, caught))},
	}
}

func TestGate0VocabularyRejectsSupplementaryEntry(t *testing.T) {
	// The supplementary-plane label sorts last under BOTH UTF-16 and
	// code-point order (every other label is ASCII), so sortedness holds and
	// the BMP-only rule is the single violation.
	bad := vocabWithDigest([]string{"egress_captured", "no_egress", "\U0001F600"}, []string{"egress_captured"})
	codes := gate0Vocabulary(bad, nil)
	if len(codes) != 1 || codes[0] != CodeVocabularyNotCanonical {
		t.Fatalf("supplementary label: codes = %v, want exactly [%s]", codes, CodeVocabularyNotCanonical)
	}

	badCaught := vocabWithDigest([]string{"egress_captured", "no_egress", "\U0001F600"}, []string{"\U0001F600"})
	codes = gate0Vocabulary(badCaught, nil)
	if len(codes) != 1 || codes[0] != CodeVocabularyNotCanonical {
		t.Fatalf("supplementary caught entry: codes = %v, want exactly [%s]", codes, CodeVocabularyNotCanonical)
	}

	good := vocabWithDigest([]string{"egress_captured", "no_egress"}, []string{"egress_captured"})
	if codes := gate0Vocabulary(good, nil); len(codes) != 0 {
		t.Fatalf("BMP-only vocabulary: unexpected codes %v", codes)
	}
}

func TestAnalyzePayloadRejectsSupplementaryMemberName(t *testing.T) {
	binding := strings.Repeat("a", 64)
	// Member names sorted identically under UTF-16 and code-point order
	// ("zz" + emoji sorts last either way), so the payload is canonical and
	// the BMP-only member-name rule is the single violation.
	bad := []byte(`{"aeeKind":"interception","aeeMethod":"intercepted","aeeRunBinding":"` + binding + `","zz` + "\U0001F600" + `":"x"}`)
	rec := &Record{PayloadType: "application/vnd.example.aee-observation.v1+json"}
	a := analyzePayload(rec, &recordState{payloadBytes: bad}, binding)
	if len(a.codes) != 1 || a.codes[0] != CodePayloadNotCanonical {
		t.Fatalf("supplementary member name: codes = %v, want exactly [%s]", a.codes, CodePayloadNotCanonical)
	}

	good := []byte(`{"aeeKind":"interception","aeeMethod":"intercepted","aeeRunBinding":"` + binding + `","zz":"` + "\U0001F600" + `"}`)
	a = analyzePayload(rec, &recordState{payloadBytes: good}, binding)
	if len(a.codes) != 0 {
		t.Fatalf("supplementary VALUE must not reject: codes = %v", a.codes)
	}
}
