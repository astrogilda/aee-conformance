package aee

// RFC 8785 (JCS) canonicalization and RFC 7493 (I-JSON) profile checks,
// implemented over the standard library only.
//
// Scope note: the conformance suite's serialization pin commits vector
// payloads with string, boolean, array, object, and I-JSON-safe integer
// values only. Integer serialization below is exact per RFC 8785. The
// non-integer (double) path implements the ES6 shortest-round-trip rules for
// the common range and is best-effort at the extreme exponent boundaries;
// any divergence there is a conservative payload-not-canonical, never a
// false accept of tampered bytes.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ErrDuplicateMember reports a JSON object with a repeated member name
// (rejected by RFC 7493).
var ErrDuplicateMember = errors.New("duplicate object member")

// ErrUnsafeInteger reports an integer with magnitude at or above 2^53
// (rejected by the predicate's I-JSON safe-integer profile, spec:67-70).
var ErrUnsafeInteger = errors.New("integer outside the I-JSON safe range")

const maxSafeInteger = int64(1) << 53 // exclusive bound: |i| must be < 2^53

// jsonObject preserves member order for duplicate detection while allowing
// canonical (sorted) emission.
type jsonObject struct {
	keys   []string
	values map[string]any
}

// parseJSONValue decodes exactly one JSON value from raw, rejecting
// duplicate members, unsafe integers, and trailing content.
func parseJSONValue(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &jsonObject{values: map[string]any{}}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object member name is not a string")
				}
				if _, dup := obj.values[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateMember, key)
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, key)
				obj.values[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			if arr == nil {
				arr = []any{}
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
	case json.Number:
		if err := checkSafeNumber(t); err != nil {
			return nil, err
		}
		return t, nil
	default:
		return tok, nil // string, bool, nil
	}
}

func checkSafeNumber(n json.Number) error {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			// Does not fit int64 at all: certainly outside the safe range.
			return fmt.Errorf("%w: %s", ErrUnsafeInteger, s)
		}
		if i >= maxSafeInteger || i <= -maxSafeInteger {
			return fmt.Errorf("%w: %s", ErrUnsafeInteger, s)
		}
	}
	return nil
}

// Canonicalize parses raw (rejecting duplicate members and unsafe integers)
// and re-emits it in RFC 8785 canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := parseJSONValue(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckIJSON reports whether raw violates the I-JSON profile the predicate
// pins: duplicate members or integers outside the safe range. Other parse
// errors are returned as-is.
func CheckIJSON(raw []byte) error {
	_, err := parseJSONValue(raw)
	return err
}

func appendCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		appendJCSString(buf, t)
	case json.Number:
		s, err := es6Number(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case *jsonObject:
		keys := append([]string(nil), t.keys...)
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendJCSString(buf, k)
			buf.WriteByte(':')
			if err := appendCanonical(buf, t.values[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value type %T", v)
	}
	return nil
}

// appendJCSString emits s with RFC 8785 string serialization: the two-char
// escapes \" \\ \b \t \n \f \r, \u00XX for remaining control characters,
// and literal UTF-8 for everything else.
func appendJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16Less orders member names by their UTF-16 code units, as RFC 8785
// section 3.2.3 requires.
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// es6Number serializes a number per RFC 8785 (ES6 Number::toString).
func es6Number(n json.Number) (string, error) {
	s := string(n)
	if !strings.ContainsAny(s, ".eE") {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrUnsafeInteger, s)
		}
		if i == 0 {
			return "0", nil // covers -0
		}
		return strconv.FormatInt(i, 10), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", err
	}
	return formatES6Float(f)
}

func formatES6Float(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("non-finite number")
	}
	if f == 0 {
		return "0", nil // covers -0
	}
	abs := math.Abs(f)
	if abs < 1e21 && abs >= 1e-6 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	// ES6 exponent form: shortest mantissa, "e+"/"e-", no zero-padded exponent.
	out := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exp, _ := strings.Cut(out, "e")
	sign := "+"
	if exp[0] == '+' || exp[0] == '-' {
		sign = string(exp[0])
		exp = exp[1:]
	}
	exp = strings.TrimLeft(exp, "0")
	if exp == "" {
		exp = "0"
	}
	return mantissa + "e" + sign + exp, nil
}
