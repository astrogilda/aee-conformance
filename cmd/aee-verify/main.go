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
	"io"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it parses args, verifies the named
// statement, writes output to stdout/stderr, and returns the process exit code
// (0 valid, 1 invalid, 2 usage or I/O error). main wraps it in os.Exit so the
// exit codes and output are exercisable without spawning a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aee-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keysPath := fs.String("keys", "", "path to the consumer key policy JSON (optional; without it every substrate row derives unattested)")
	jsonOut := fs.Bool("json", false, "emit the full report as JSON")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: aee-verify [-keys policy.json] [-json] <statement.json>\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	policy, err := loadPolicy(*keysPath)
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}
	body, err := os.ReadFile(fs.Arg(0)) // #nosec G304 -- this CLI verifies a file the operator names by design
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}

	report, err := verifySafely(body, policy)
	if err != nil {
		fmt.Fprintf(stderr, "aee-verify: %v\n", err)
		return 2
	}
	if *jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "aee-verify: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		printHuman(stdout, report)
	}
	if report.Verdict != aee.VerdictValid {
		return 1
	}
	return 0
}

// verifySafely runs aee.Verify with a panic backstop. aee.Verify is written to
// never panic on any input, but this CLI ingests untrusted attestation bytes, so
// a recover keeps a hypothetical verifier bug from crashing the process: it maps
// to the I/O-error exit code with a diagnostic rather than a stack trace.
func verifySafely(body []byte, policy *aee.KeyPolicy) (report *aee.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			report, err = nil, fmt.Errorf("internal verifier panic: %v", r)
		}
	}()
	return aee.Verify(body, policy), nil
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

func printHuman(w io.Writer, r *aee.Report) {
	fmt.Fprintf(w, "verdict: %s\n", r.Verdict)
	if r.Verdict != aee.VerdictValid {
		for _, c := range r.Codes {
			marker := " "
			if c == r.PrimaryCode {
				marker = "*"
			}
			fmt.Fprintf(w, "  %s %s\n", marker, c)
		}
		fmt.Fprintln(w, "result: (not consumed — the attestation is invalid)")
		return
	}
	fmt.Fprintf(w, "result: %s (recompute-confirmed)\n", r.Result)
	fmt.Fprintln(w, "evidence tiers (per attackResults row, per YOUR key policy):")
	for i, tier := range r.Tiers {
		fmt.Fprintf(w, "  row %d: %s\n", i, tier)
	}
}
