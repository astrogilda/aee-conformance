// Command aee-verify is the consumer MVP for AEE v0.6 statements: it runs
// GATE 0 (well-formedness), GATE 1 (coverage validity), the result
// recompute, and derives the per-row evidence tier against a consumer key
// policy. Exit codes: 0 valid, 1 invalid, 2 usage or I/O error.
//
// Key policy file (JSON; pinned out of band, never read from the predicate):
//
//	{"substrateObservationKeys": [
//	  {"keyid": "<hint, optional>", "publicKeyHex": "<64-hex raw ed25519 public key>"}
//	]}
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/astrogilda/aee-conformance/aee"
)

type keyFile struct {
	SubstrateObservationKeys []struct {
		KeyID        string `json:"keyid"`
		PublicKeyHex string `json:"publicKeyHex"`
	} `json:"substrateObservationKeys"`
}

func main() {
	keysPath := flag.String("keys", "", "path to the consumer key policy JSON (optional; without it every substrate row derives unattested)")
	jsonOut := flag.Bool("json", false, "emit the full report as JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: aee-verify [-keys policy.json] [-json] <statement.json>\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	policy, err := loadPolicy(*keysPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aee-verify: %v\n", err)
		os.Exit(2)
	}
	body, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "aee-verify: %v\n", err)
		os.Exit(2)
	}

	report := aee.Verify(body, policy)
	if *jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "aee-verify: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(out))
	} else {
		printHuman(report)
	}
	if report.Verdict != aee.VerdictValid {
		os.Exit(1)
	}
}

func loadPolicy(path string) (*aee.KeyPolicy, error) {
	if path == "" {
		return nil, nil // no policy: every substrate row derives unattested (no TOFU)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- this CLI verifies a policy file the operator names by design
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("key policy does not parse: %w", err)
	}
	policy := &aee.KeyPolicy{}
	for _, k := range kf.SubstrateObservationKeys {
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: publicKeyHex must be %d hex-encoded bytes", k.KeyID, ed25519.PublicKeySize)
		}
		policy.SubstrateObservationKeys = append(policy.SubstrateObservationKeys, ed25519.PublicKey(pub))
	}
	return policy, nil
}

func printHuman(r *aee.Report) {
	fmt.Printf("verdict: %s\n", r.Verdict)
	if r.Verdict != aee.VerdictValid {
		for _, c := range r.Codes {
			marker := " "
			if c == r.PrimaryCode {
				marker = "*"
			}
			fmt.Printf("  %s %s\n", marker, c)
		}
		fmt.Println("result: (not consumed — the attestation is invalid)")
		return
	}
	fmt.Printf("result: %s (recompute-confirmed)\n", r.Result)
	fmt.Println("evidence tiers (per attackResults row, per YOUR key policy):")
	for i, tier := range r.Tiers {
		fmt.Printf("  row %d: %s\n", i, tier)
	}
}
