package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// gateLine renders one request line carrying raw as a base64 gate candidate.
func gateLine(id int64, mode string, raw []byte) string {
	req := request{ID: id, Mode: mode, InputB64: base64.StdEncoding.EncodeToString(raw)}
	b, _ := json.Marshal(req)
	return string(b)
}

func runLines(t *testing.T, lines ...string) []response {
	t.Helper()
	var out, errb bytes.Buffer
	run(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out, &errb)
	var resps []response
	for _, ln := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if ln == "" {
			continue
		}
		var r response
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("unmarshal response %q: %v", ln, err)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestGateAcceptsWellFormed(t *testing.T) {
	r := runLines(t, gateLine(1, "gate", []byte(`{"a":1}`)))
	if len(r) != 1 || !r[0].Accept || r[0].Rail != "aee" {
		t.Fatalf("expected one accept from rail aee, got %+v", r)
	}
}

func TestGateRejectsNoncharacter(t *testing.T) {
	// U+FFFF in a value is an RFC 7493 noncharacter.
	r := runLines(t, gateLine(2, "gate", []byte("{\"a\":\"￿\"}")))
	if len(r) != 1 || r[0].Accept || r[0].Reason == "" {
		t.Fatalf("expected a reasoned reject, got %+v", r)
	}
}

func TestGateRejectsOverDeep(t *testing.T) {
	// 129 open containers with a scalar leaf: one past the depth bound.
	deep := strings.Repeat(`{"a":`, 129) + "1" + strings.Repeat("}", 129)
	r := runLines(t, gateLine(3, "gate", []byte(deep)))
	if len(r) != 1 || r[0].Accept {
		t.Fatalf("expected a reject at depth 129, got %+v", r)
	}
}

func TestBadBase64IsReported(t *testing.T) {
	r := runLines(t, `{"id":4,"mode":"gate","input_b64":"@@not-base64@@"}`)
	if len(r) != 1 || r[0].Accept || !strings.Contains(r[0].Reason, "bad input_b64") {
		t.Fatalf("expected a bad-input_b64 reject, got %+v", r)
	}
}

func TestUnknownModeIsReported(t *testing.T) {
	r := runLines(t, gateLine(5, "canon", []byte(`{"a":1}`)))
	if len(r) != 1 || r[0].Accept || !strings.Contains(r[0].Reason, "unknown mode") {
		t.Fatalf("expected an unknown-mode reject, got %+v", r)
	}
}

func TestMalformedControlLineIsReported(t *testing.T) {
	r := runLines(t, `this is not json`)
	if len(r) != 1 || r[0].Accept || !strings.Contains(r[0].Reason, "bad request") {
		t.Fatalf("expected a bad-request reject, got %+v", r)
	}
}

func TestEmptyLinesAreSkipped(t *testing.T) {
	r := runLines(t, "", gateLine(6, "gate", []byte(`{"a":1}`)), "")
	if len(r) != 1 || !r[0].Accept {
		t.Fatalf("expected empty lines skipped and one accept, got %+v", r)
	}
}
