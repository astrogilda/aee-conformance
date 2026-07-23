package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astrogilda/aee-conformance/aeetest"
)

func writeTemp(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "statement.json")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunValidStatementExit0(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{path}, &out, &errb); code != 0 {
		t.Fatalf("valid statement: exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("expected valid verdict, got:\n%s", out.String())
	}
}

func TestRunInvalidStatementExit1(t *testing.T) {
	// Result forced to "pass" against a caught row: recompute mismatch.
	path := writeTemp(t, aeetest.Build(aeetest.Options{Result: "pass"}))
	var out, errb bytes.Buffer
	code := run([]string{path}, &out, &errb)
	if code != 1 {
		t.Fatalf("invalid statement: exit %d (want 1), stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: invalid") {
		t.Fatalf("expected invalid verdict, got:\n%s", out.String())
	}
}

func TestRunJSONOutput(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{"-json", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	var report struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if report.Verdict != "valid" {
		t.Fatalf("json verdict = %q, want valid", report.Verdict)
	}
}

func TestRunMissingFileExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{filepath.Join(t.TempDir(), "nope.json")}, &out, &errb); code != 2 {
		t.Fatalf("missing file: exit %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "aee-verify:") {
		t.Fatalf("expected an error diagnostic on stderr, got %q", errb.String())
	}
}

func TestRunUsageExit2(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}
}

func TestRunUnknownFlagExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-nope", "x"}, &out, &errb); code != 2 {
		t.Fatalf("unknown flag: exit %d, want 2", code)
	}
}

func keyPolicyFile(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	body := fmt.Sprintf(`{"substrateObservationKeys":[{"keyid":"k1","publicKeyHex":%q}]}`,
		hex.EncodeToString(pub))
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunPinnedKeyAttestedAdmitted(t *testing.T) {
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)
	var out, errb bytes.Buffer
	if code := run([]string{"-keys", keys, statement}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "attested") {
		t.Fatalf("pinned covering key should derive attested, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "admitted: true") {
		t.Fatalf("expected admitted: true, got:\n%s", out.String())
	}
}

func TestRunWrongKeyUnattestedNotAdmitted(t *testing.T) {
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	// A different key than the record signer: the covering record cannot
	// verify, the row derives unattested, and with a policy supplied the
	// exit status binds to the admission result, not bare validity.
	pub := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)
	var out, errb bytes.Buffer
	if code := run([]string{"-keys", keys, statement}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1 (valid but not admitted), stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("statement stays byte-pure valid, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "unattested") {
		t.Fatalf("wrong key should derive unattested, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "admitted: false") {
		t.Fatalf("expected admitted: false, got:\n%s", out.String())
	}
}

// corpusAndSubstrateDigests reads the carried anchor digests out of a built
// statement, so the anchor tests compare against exactly what travels.
func corpusAndSubstrateDigests(t *testing.T, body []byte) (corpus, substrate string) {
	t.Helper()
	var stmt struct {
		Predicate struct {
			Env struct {
				Corpus struct {
					Digest map[string]string `json:"digest"`
				} `json:"corpus"`
				Substrate struct {
					Digest map[string]string `json:"digest"`
				} `json:"substrate"`
			} `json:"observationEnvironment"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	return stmt.Predicate.Env.Corpus.Digest["sha256"], stmt.Predicate.Env.Substrate.Digest["sha256"]
}

func TestRunAnchorsBindExitToAdmission(t *testing.T) {
	body := aeetest.Build(aeetest.Options{})
	statement := writeTemp(t, body)
	corpus, substrate := corpusAndSubstrateDigests(t, body)
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)

	// Matching anchors + covering key: admitted, exit 0.
	var out, errb bytes.Buffer
	code := run([]string{"-keys", keys,
		"-expected-corpus-digest", corpus,
		"-expected-substrate-digest", substrate, statement}, &out, &errb)
	if code != 0 {
		t.Fatalf("matching anchors: exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "corpus anchor: match") ||
		!strings.Contains(out.String(), "substrate anchor: match") {
		t.Fatalf("expected anchor match lines, got:\n%s", out.String())
	}

	// Mismatched corpus anchor: still valid, not admitted, exit 1.
	out.Reset()
	errb.Reset()
	code = run([]string{"-keys", keys,
		"-expected-corpus-digest", strings.Repeat("0", 64), statement}, &out, &errb)
	if code != 1 {
		t.Fatalf("mismatched anchor: exit %d, want 1, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("anchor mismatch must not fail validity, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "corpus-anchor-mismatch") {
		t.Fatalf("expected the corpus-anchor-mismatch code surfaced, got:\n%s", out.String())
	}

	// An anchor flag alone supplies a policy: with no keys the substrate row
	// derives unattested, so the statement is not admitted even though the
	// anchor matches.
	out.Reset()
	errb.Reset()
	code = run([]string{"-expected-corpus-digest", corpus, statement}, &out, &errb)
	if code != 1 {
		t.Fatalf("anchor-only policy on a substrate statement: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "tier policy: NOT satisfied") {
		t.Fatalf("expected the tier-policy fact, got:\n%s", out.String())
	}
}

func TestRunBareModeBindsExitToValidity(t *testing.T) {
	// Bare conformance-replay mode: no policy supplied, so a valid statement
	// exits 0 even though its substrate row is unattested under no-TOFU.
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{statement}, &out, &errb); code != 0 {
		t.Fatalf("bare mode valid statement: exit %d, stderr=%q", code, errb.String())
	}
	if strings.Contains(out.String(), "admitted:") {
		t.Fatalf("bare mode must not print an admission decision, got:\n%s", out.String())
	}
}

func TestLoadPolicy(t *testing.T) {
	// nothing supplied -> no policy, no error
	if p, err := loadPolicy("", "", ""); p != nil || err != nil {
		t.Fatalf("no policy inputs: got (%v,%v), want (nil,nil)", p, err)
	}
	// anchors without a key file still form a policy
	if p, err := loadPolicy("", "aa", "bb"); err != nil || p == nil ||
		p.ExpectedCorpusDigest != "aa" || p.ExpectedSubstrateDigest != "bb" ||
		len(p.SubstrateObservationKeys) != 0 {
		t.Fatalf("anchor-only policy: got (%+v,%v)", p, err)
	}
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "k.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// malformed JSON
	if _, err := loadPolicy(write("{"), "", ""); err == nil {
		t.Fatal("malformed JSON policy should error")
	}
	// non-hex public key
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"zz"}]}`), "", ""); err == nil {
		t.Fatal("non-hex publicKeyHex should error")
	}
	// wrong-length key (valid hex, too short)
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"aabb"}]}`), "", ""); err == nil {
		t.Fatal("short publicKeyHex should error")
	}
	// valid key
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	p, err := loadPolicy(keyPolicyFile(t, pub), "", "")
	if err != nil || p == nil || len(p.SubstrateObservationKeys) != 1 {
		t.Fatalf("valid policy: got (%v,%v)", p, err)
	}
}
