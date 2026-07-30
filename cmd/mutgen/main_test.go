package main

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture exercises every operator mutgen claims to have. It is compiled by
// nothing, so it may name types the rail defines (Code, appendCode) without
// importing anything: the mutator is purely syntactic and never typechecks.
const fixture = `package rail

type Code string

func appendCode(cs []Code, c Code) []Code { return append(cs, c) }

const CodeA Code = "a"

type ev struct{ valid bool }

func Guard(a, b, c bool, codes []Code) []Code {
	if a {
		codes = appendCode(codes, CodeA)
	}
	if a || b {
		codes = appendCode(codes, CodeA)
	}
	if a && b {
		codes = appendCode(codes, CodeA)
	}
	switch {
	case c:
		codes = appendCode(codes, CodeA)
	case a || b:
		codes = appendCode(codes, CodeA)
	case a && b:
		codes = appendCode(codes, CodeA)
	}
	return codes
}

func Kind(s string) string {
	switch s {
	case "one":
		return "1"
	case "two":
		return "2"
	}
	return ""
}

func Pred(a, b bool) bool {
	if a {
		return b
	}
	return false
}

func Assign(e *ev, a bool) {
	e.valid = a
}
`

func fixturePkg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// A _test.go file in the same directory must be ignored: mutating a test
	// would measure the tests rather than the rail.
	if err := os.WriteFile(filepath.Join(dir, "rail_test.go"), []byte("package rail\n\nfunc Ignored(a bool) bool {\n\tif a {\n\t\treturn true\n\t}\n\treturn false\n}\n"), 0o600); err != nil {
		t.Fatalf("write test fixture: %v", err)
	}
	return dir
}

func listSites(t *testing.T, dir string) []site {
	t.Helper()
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-list"}, &out, &errs); code != 0 {
		t.Fatalf("-list exited %d: %s", code, errs.String())
	}
	var sites []site
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var s site
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		sites = append(sites, s)
	}
	return sites
}

func TestListCoversEveryOperator(t *testing.T) {
	sites := listSites(t, fixturePkg(t))
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.Op] = true
		if s.File != "rail.go" {
			t.Errorf("site %s came from %s; only non-test sources may be enumerated", s.Key, s.File)
		}
	}
	for _, op := range []string{
		"IF_OFF", "IF_DISJ", "IF_CONJ", "CASE_OFF", "CASE_DISJ", "CASE_CONJ",
		"CASE_DEL", "RET_TRUE", "RET_FALSE", "CODE_OFF", "VALID_TRUE",
	} {
		if !seen[op] {
			t.Errorf("operator %s produced no site; the fixture or the enumerator lost it", op)
		}
	}
}

// A key that moved when unrelated lines moved would make the forcing baseline
// unusable as a ratchet: one inserted rule would read as several hundred
// simultaneous regressions.
func TestKeysAreStableUnderLineShifts(t *testing.T) {
	before := listSites(t, fixturePkg(t))

	shifted := t.TempDir()
	body := "package rail\n\n// a comment that did not exist\n// and a second line of it\n" +
		strings.TrimPrefix(fixture, "package rail\n")
	if err := os.WriteFile(filepath.Join(shifted, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	after := listSites(t, shifted)

	if len(before) != len(after) {
		t.Fatalf("site count changed under a comment insertion: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Key != after[i].Key {
			t.Errorf("key moved under a line shift: %s -> %s", before[i].Key, after[i].Key)
		}
		if before[i].Line == after[i].Line {
			t.Errorf("site %s did not move at all; the fixture failed to shift anything", before[i].Key)
		}
	}
}

// Two identical sites in one function are exactly what `if err != nil { return
// err }` produces, and they must not collide into one baseline row.
func TestRepeatedSitesAreSeparatedByOrdinal(t *testing.T) {
	dir := t.TempDir()
	// Byte-identical guards, which is what a repeated `if err != nil { return err }`
	// looks like to a syntactic mutator.
	body := "package rail\n\nfunc Twice(a bool) int {\n\tif a {\n\t\treturn 1\n\t}\n\tif a {\n\t\treturn 1\n\t}\n\treturn 3\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sites := listSites(t, dir)
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(sites))
	}
	if sites[0].Key == sites[1].Key {
		t.Fatalf("two identical sites collided on one key: %s", sites[0].Key)
	}
	if !strings.HasSuffix(sites[1].Key, "#2") {
		t.Errorf("the second occurrence should carry an ordinal, got %s", sites[1].Key)
	}
}

// Every mutation must still PARSE: a mutant that does not compile scores as
// inconclusive, which measures nothing. Parsing is the strongest check available
// without a typechecker, and it catches the whole class of naive rewrites (a bare
// `false` in a tagged case arm, a deleted clause that strands a comment).
func TestEveryMutationStillParses(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	if len(sites) == 0 {
		t.Fatal("no sites")
	}
	for _, s := range sites {
		var out, errs bytes.Buffer
		if code := run([]string{"-pkg", dir, "-apply", s.Key}, &out, &errs); code != 0 {
			t.Fatalf("-apply %s exited %d: %s", s.Key, code, errs.String())
		}
		if out.String() == fixture {
			t.Errorf("-apply %s changed nothing", s.Key)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), "mutant.go", out.String(), 0); err != nil {
			t.Errorf("-apply %s produced unparseable Go: %v\n%s", s.Key, err, out.String())
		}
	}
}

func TestApplyWriteRewritesTheFileInPlace(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	target := sites[0]
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-apply", target.Key, "-write"}, &out, &errs); code != 0 {
		t.Fatalf("exited %d: %s", code, errs.String())
	}
	if out.Len() != 0 {
		t.Errorf("-write should not also print to stdout, got %d bytes", out.Len())
	}
	body, err := os.ReadFile(filepath.Join(dir, "rail.go"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(body) == fixture {
		t.Fatal("-write left the file unchanged")
	}
	if !strings.Contains(string(body), "false && (") {
		t.Errorf("expected a short-circuited guard in the rewritten file:\n%s", body)
	}
}

func TestUsageFailures(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no package", []string{"-list"}, "-pkg is required"},
		{"neither mode", []string{"-pkg", "."}, "exactly one of"},
		{"both modes", []string{"-pkg", ".", "-list", "-apply", "x"}, "exactly one of"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"missing package", []string{"-pkg", filepath.Join(t.TempDir(), "absent"), "-list"}, "no such file"},
		{"key names no file", []string{"-pkg", ".", "-apply", "nonsense"}, "does not name a source file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			if code := run(tc.args, &out, &errs); code != 2 {
				t.Fatalf("exited %d, want 2", code)
			}
			if !strings.Contains(errs.String(), tc.want) {
				t.Errorf("stderr %q does not carry %q", errs.String(), tc.want)
			}
		})
	}
}

func TestApplyUnknownKeyIsRefused(t *testing.T) {
	dir := fixturePkg(t)
	var out, errs bytes.Buffer
	code := run([]string{"-pkg", dir, "-apply", "rail.go::Guard::IF_OFF::000000000000"}, &out, &errs)
	if code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
	if !strings.Contains(errs.String(), "no site") {
		t.Errorf("stderr %q does not name the missing site", errs.String())
	}
}

func TestApplyUnparseablePackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte("package rail\nfunc ("), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, args := range [][]string{
		{"-pkg", dir, "-list"},
		{"-pkg", dir, "-apply", "rail.go::x::IF_OFF::000000000000"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != 2 {
			t.Errorf("%v exited %d, want 2", args, code)
		}
	}
}

func TestWriteToAnUnwritablePathIsRefused(t *testing.T) {
	dir := fixturePkg(t)
	sites := listSites(t, dir)
	target := filepath.Join(dir, "rail.go")
	if err := os.Chmod(target, 0o400); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })
	if os.Geteuid() == 0 {
		t.Skip("running as root, where a read-only file is still writable")
	}
	var out, errs bytes.Buffer
	if code := run([]string{"-pkg", dir, "-apply", sites[0].Key, "-write"}, &out, &errs); code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
}

func TestSiteKeyOrdinalAndFileRecovery(t *testing.T) {
	first := siteKey("validity.go", "checkRow", "IF_OFF", "if a {}", 1)
	second := siteKey("validity.go", "checkRow", "IF_OFF", "if a {}", 2)
	if first == second {
		t.Fatal("ordinal did not separate two identical sites")
	}
	if got := fileOfKey(first); got != "validity.go" {
		t.Errorf("fileOfKey(%q) = %q", first, got)
	}
	if got := fileOfKey("nofile"); got != "nofile" {
		t.Errorf("fileOfKey on a keyless string = %q", got)
	}
}

func TestSnippetIsBounded(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("aaaaaaaaaa || ", 40) + "b"
	body := "package rail\n\nfunc Long(aaaaaaaaaa, b bool) int {\n\tif " + long + " {\n\t\treturn 1\n\t}\n\treturn 0\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "rail.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, s := range listSites(t, dir) {
		if len(s.Snippet) > maxSnippet+3 {
			t.Errorf("snippet of %s is %d characters, over the %d bound", s.Key, len(s.Snippet), maxSnippet)
		}
	}
}

// apply reports rather than silently succeeding when the node it was handed is
// not reachable from the file it was handed.
func TestApplyRefusesAnUnreachableNode(t *testing.T) {
	dir := fixturePkg(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(dir, "rail.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sites := collect(fset, f, "rail.go")
	var expr *site
	for _, s := range sites {
		if s.kind == "expr" {
			expr = s
			break
		}
	}
	if expr == nil {
		t.Fatal("no expression site in the fixture")
	}
	other, err := parser.ParseFile(fset, "other.go", "package rail\n\nfunc Other() {}\n", 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := apply(other, expr); err == nil {
		t.Fatal("apply reported success for a node the file does not contain")
	}
}
