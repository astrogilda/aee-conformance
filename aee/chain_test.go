package aee

// Unit tests for the arming-payload run-chaining member syntax
// (aeeRunSeq / aeePrevRunBinding / aeeChainScope): syntax-only checks in
// the reserved-member walk; nothing else normative reads the members.

import (
	"strings"
	"testing"
)

func parseObj(t *testing.T, raw string) *jsonObject {
	t.Helper()
	v, err := parseJSONValue([]byte(raw))
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	obj, ok := v.(*jsonObject)
	if !ok {
		t.Fatalf("%q is not an object", raw)
	}
	return obj
}

func TestArmingChainSyntax(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"no chain members", `{}`, true},
		{"genesis: seq 1, scope, no prev", `{"aeeChainScope":["subject"],"aeeRunSeq":1}`, true},
		{"link: seq 2, scope, 64-hex prev", `{"aeeChainScope":["subject"],"aeePrevRunBinding":"` + hex64 + `","aeeRunSeq":2}`, true},
		{"multi-token canonical scope", `{"aeeChainScope":["corpus","subject"],"aeeRunSeq":1}`, true},
		{"empty scope array (global counter)", `{"aeeChainScope":[],"aeeRunSeq":1}`, true},
		{"seq 0 is not positive", `{"aeeChainScope":["subject"],"aeeRunSeq":0}`, false},
		{"negative seq", `{"aeeChainScope":["subject"],"aeeRunSeq":-1}`, false},
		{"seq without scope", `{"aeeRunSeq":1}`, false},
		{"seq with non-array scope (string)", `{"aeeChainScope":"subject","aeeRunSeq":1}`, false},
		{"seq with non-array scope (number)", `{"aeeChainScope":7,"aeeRunSeq":1}`, false},
		{"scope with unknown dimension token", `{"aeeChainScope":["bogus"],"aeeRunSeq":1}`, false},
		{"scope not in canonical order", `{"aeeChainScope":["subject","corpus"],"aeeRunSeq":1}`, false},
		{"scope with duplicate token", `{"aeeChainScope":["subject","subject"],"aeeRunSeq":1}`, false},
		{"scope element not a string", `{"aeeChainScope":[7],"aeeRunSeq":1}`, false},
		{"non-integer seq", `{"aeeChainScope":["subject"],"aeeRunSeq":"1"}`, false},
		{"genesis with a predecessor", `{"aeeChainScope":["subject"],"aeePrevRunBinding":"` + hex64 + `","aeeRunSeq":1}`, false},
		{"link without a predecessor", `{"aeeChainScope":["subject"],"aeeRunSeq":2}`, false},
		{"prev not 64-hex", `{"aeeChainScope":["subject"],"aeePrevRunBinding":"EXAMPLE-NOT-HEX","aeeRunSeq":2}`, false},
		{"prev uppercase hex", `{"aeeChainScope":["subject"],"aeePrevRunBinding":"` + strings.ToUpper(hex64) + `","aeeRunSeq":2}`, false},
		{"prev without seq", `{"aeePrevRunBinding":"` + hex64 + `"}`, false},
		{"scope without seq", `{"aeeChainScope":["subject"]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := armingChainSyntaxValid(parseObj(t, tc.raw)); got != tc.want {
				t.Fatalf("armingChainSyntaxValid(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
