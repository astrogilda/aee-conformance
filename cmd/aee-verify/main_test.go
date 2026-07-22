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

func TestRunPinnedKeyAttested(t *testing.T) {
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
}

func TestRunWrongKeyUnattested(t *testing.T) {
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	// A different key than the record signer: the covering record cannot verify.
	pub := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)
	var out, errb bytes.Buffer
	if code := run([]string{"-keys", keys, statement}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "unattested") {
		t.Fatalf("wrong key should derive unattested, got:\n%s", out.String())
	}
}

func TestLoadPolicy(t *testing.T) {
	// empty path -> no policy, no error
	if p, err := loadPolicy(""); p != nil || err != nil {
		t.Fatalf("empty path: got (%v,%v), want (nil,nil)", p, err)
	}
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "k.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// malformed JSON
	if _, err := loadPolicy(write("{")); err == nil {
		t.Fatal("malformed JSON policy should error")
	}
	// non-hex public key
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"zz"}]}`)); err == nil {
		t.Fatal("non-hex publicKeyHex should error")
	}
	// wrong-length key (valid hex, too short)
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"aabb"}]}`)); err == nil {
		t.Fatal("short publicKeyHex should error")
	}
	// valid key
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	p, err := loadPolicy(keyPolicyFile(t, pub))
	if err != nil || p == nil || len(p.SubstrateObservationKeys) != 1 {
		t.Fatalf("valid policy: got (%v,%v)", p, err)
	}
}
