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
		{"genesis: seq 1, scope, no prev", `{"aeeChainScope":"s","aeeRunSeq":1}`, true},
		{"link: seq 2, scope, 64-hex prev", `{"aeeChainScope":"s","aeePrevRunBinding":"` + hex64 + `","aeeRunSeq":2}`, true},
		{"seq 0 is not positive", `{"aeeChainScope":"s","aeeRunSeq":0}`, false},
		{"negative seq", `{"aeeChainScope":"s","aeeRunSeq":-1}`, false},
		{"seq without scope", `{"aeeRunSeq":1}`, false},
		{"seq with non-string scope", `{"aeeChainScope":7,"aeeRunSeq":1}`, false},
		{"non-integer seq", `{"aeeChainScope":"s","aeeRunSeq":"1"}`, false},
		{"genesis with a predecessor", `{"aeeChainScope":"s","aeePrevRunBinding":"` + hex64 + `","aeeRunSeq":1}`, false},
		{"link without a predecessor", `{"aeeChainScope":"s","aeeRunSeq":2}`, false},
		{"prev not 64-hex", `{"aeeChainScope":"s","aeePrevRunBinding":"EXAMPLE-NOT-HEX","aeeRunSeq":2}`, false},
		{"prev uppercase hex", `{"aeeChainScope":"s","aeePrevRunBinding":"` + strings.ToUpper(hex64) + `","aeeRunSeq":2}`, false},
		{"prev without seq", `{"aeePrevRunBinding":"` + hex64 + `"}`, false},
		{"scope without seq", `{"aeeChainScope":"s"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := armingChainSyntaxValid(parseObj(t, tc.raw)); got != tc.want {
				t.Fatalf("armingChainSyntaxValid(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
