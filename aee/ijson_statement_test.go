package aee

// Statement-wide strict I-JSON (RFC 7493): a duplicate member anywhere in the
// statement JSON, not only inside a covering record payload, makes the
// statement malformed. stdlib json.Unmarshal silently keeps the last of a
// repeated member, so ParseStatement runs the I-JSON-strict parser over the
// whole document.

import "testing"

func TestStatementWideDuplicateMemberRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool // true => ParseStatement must return an error
	}{
		{
			"top-level duplicate member",
			`{"_type":"https://in-toto.io/Statement/v1","_type":"x","subject":[],"predicateType":"p","predicate":{}}`,
			true,
		},
		{
			"nested duplicate member inside predicate",
			`{"_type":"t","subject":[],"predicateType":"p","predicate":{"a":1,"a":2}}`,
			true,
		},
		{
			"clean statement (control)",
			`{"_type":"t","subject":[],"predicateType":"p","predicate":{"a":1,"b":2}}`,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseStatement([]byte(tc.raw))
			if tc.want && err == nil {
				t.Fatalf("ParseStatement(%s) = nil error, want rejection", tc.raw)
			}
			if !tc.want && err != nil {
				t.Fatalf("ParseStatement(%s) = %v, want no error", tc.raw, err)
			}
		})
	}
}
