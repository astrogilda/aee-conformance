package witnessattestor

import (
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
)

// TestMatchConfiguredEvidence pins the path-boundary match: a configured
// evidence-path never matches a substring of a filename (the loose-suffix bug
// that let "evidence.json" resolve to "attacker-evidence.json"), and a value
// that resolves to more than one product fails closed instead of signing a
// nondeterministic map-iteration winner.
func TestMatchConfiguredEvidence(t *testing.T) {
	p := func(names ...string) map[string]attestation.Product {
		m := make(map[string]attestation.Product, len(names))
		for _, n := range names {
			m[n] = attestation.Product{}
		}
		return m
	}
	tests := []struct {
		name       string
		products   map[string]attestation.Product
		configured string
		wantPath   string   // "" => expect error
		errNeedles []string // substrings the error must contain
	}{
		{
			name:       "attacker prefix does not match on a filename substring",
			products:   p("attacker-evidence.json"),
			configured: "evidence.json",
			errNeedles: []string{"not among"},
		},
		{
			name:       "exact and segment both match is ambiguous, fail closed",
			products:   p("evidence.json", "sub/evidence.json"),
			configured: "evidence.json",
			errNeedles: []string{"ambiguous", "evidence.json", "sub/evidence.json"},
		},
		{
			name:       "single trailing segment match resolves",
			products:   p("sub/dir/evidence.json", "other.txt"),
			configured: "evidence.json",
			wantPath:   "sub/dir/evidence.json",
		},
		{
			name:       "exact full-path match is unambiguous next to an attacker prefix",
			products:   p("a/b/evidence.json", "attacker-a/b/evidence.json"),
			configured: "a/b/evidence.json",
			wantPath:   "a/b/evidence.json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := matchConfiguredEvidence(tc.products, tc.configured)
			if tc.wantPath == "" {
				if err == nil {
					t.Fatalf("want error, got path %q", got)
				}
				for _, needle := range tc.errNeedles {
					if !strings.Contains(err.Error(), needle) {
						t.Fatalf("error %q missing %q", err.Error(), needle)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("want path %q, got error %v", tc.wantPath, err)
			}
			if got != tc.wantPath {
				t.Fatalf("want path %q, got %q", tc.wantPath, got)
			}
		})
	}
}
