package aee

import (
	"errors"
	"fmt"
	"testing"
)

// TestJCSStringEscapes pins RFC 8785 (section 3.2.2.2) string serialization on
// the canonicalizer. Inputs are built programmatically so the source carries no
// raw control bytes; the canonical form must re-derive the required escaping.
func TestJCSStringEscapes(t *testing.T) {
	// The five short two-char escapes: the control code point serializes to its
	// backslash-letter form.
	short := map[rune]string{'\b': `\b`, '\t': `\t`, '\n': `\n`, '\f': `\f`, '\r': `\r`}
	for r, esc := range short {
		in := fmt.Sprintf(`"\u%04x"`, r) // JSON string carrying the \u escape
		want := `"` + esc + `"`
		if got, err := Canonicalize([]byte(in)); err != nil || string(got) != want {
			t.Errorf("short escape U+%04X: got %q want %q err %v", r, string(got), want, err)
		}
	}

	// Every other C0 control serializes to lowercase \u00xx, regardless of the
	// input escape's case.
	for _, r := range []rune{0x00, 0x01, 0x07, 0x0b, 0x1f} {
		in := fmt.Sprintf(`"\u%04X"`, r)   // uppercase-hex escape in
		want := fmt.Sprintf(`"\u%04x"`, r) // lowercase-hex escape out
		if got, err := Canonicalize([]byte(in)); err != nil || string(got) != want {
			t.Errorf("C0 control U+%04X: got %q want %q err %v", r, string(got), want, err)
		}
	}

	// BMP code points >= 0x20 -- including DEL -- are emitted as literal UTF-8
	// and MUST NOT be \u-escaped.
	for _, r := range []rune{'A', 0x7f, 0x00e9, 0x20ac} {
		in := fmt.Sprintf(`"\u%04x"`, r)
		want := `"` + string(r) + `"`
		if got, err := Canonicalize([]byte(in)); err != nil || string(got) != want {
			t.Errorf("literal U+%04X: got %q want %q err %v", r, string(got), want, err)
		}
	}

	// An astral code point is emitted as literal 4-byte UTF-8, never \u-escaped.
	{
		in := `"😀"` // U+1F600
		want := `"` + string(rune(0x1F600)) + `"`
		if got, err := Canonicalize([]byte(in)); err != nil || string(got) != want {
			t.Errorf("astral surrogate pair: got %q want %q err %v", string(got), want, err)
		}
	}

	// Quote and backslash escape; solidus does not.
	for _, tc := range []struct{ in, want string }{
		{`"\""`, `"\""`},
		{`"\\"`, `"\\"`},
		{`"\/"`, `"/"`},
		{`"a\tb\nc"`, `"a\tb\nc"`},
	} {
		if got, err := Canonicalize([]byte(tc.in)); err != nil || string(got) != tc.want {
			t.Errorf("Canonicalize(%q) = %q want %q err %v", tc.in, string(got), tc.want, err)
		}
	}
}

// TestJCSNestedDuplicateKey proves duplicate members are rejected (RFC 7493 /
// RFC 8785) when nested, not only at the top level.
func TestJCSNestedDuplicateKey(t *testing.T) {
	nested := []byte(`{"outer":{"k":1,"k":2}}`)
	if _, err := Canonicalize(nested); !errors.Is(err, ErrDuplicateMember) {
		t.Fatalf("Canonicalize(nested dup): want ErrDuplicateMember, got %v", err)
	}
	if err := CheckIJSON(nested); !errors.Is(err, ErrDuplicateMember) {
		t.Fatalf("CheckIJSON(nested dup): want ErrDuplicateMember, got %v", err)
	}
	// A dup inside an array element is also rejected.
	if _, err := Canonicalize([]byte(`[{"k":1,"k":2}]`)); !errors.Is(err, ErrDuplicateMember) {
		t.Fatalf("dup in array element: want ErrDuplicateMember, got %v", err)
	}
}
