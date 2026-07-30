// Command mutgen enumerates and applies single-site WEAKENING mutations to the
// Go verification rail, so that what the conformance corpus FORCES can be
// measured instead of asserted.
//
// A vector count is an upper bound on forcing and never a measurement of it. The
// question a relying party actually has is: if a rule vanished from a verifier,
// would this corpus notice? That is answered by removing exactly one rule and
// replaying the whole corpus. Every operator below makes the rail strictly MORE
// PERMISSIVE at one syntactic site, which is the direction the question asks
// about:
//
//	IF_OFF      if COND {...}          -> if false && (COND) {...}   whole guard off
//	IF_DISJ     if A || B {...}        -> if (false && (A)) || B     one disjunct off
//	IF_CONJ     if A && B {...}        -> if (true || (A)) && B      one conjunct off
//	CASE_OFF    switch { case C: }     -> case false && (C):         tagless switch arm off
//	CASE_DISJ   as IF_DISJ, in a tagless switch arm
//	CASE_CONJ   as IF_CONJ, in a tagless switch arm
//	CASE_DEL    switch T { case V: }   -> the arm is deleted         tagged/type switch arm off
//	RET_TRUE    return <boolexpr>      -> return true || (<expr>)    bool predicate arm
//	RET_FALSE   return <boolexpr>      -> return false && (<expr>)
//	CODE_OFF    appendCode(cs, CodeX)  -> cs                         one emission off
//	VALID_TRUE  ev.valid = <expr>      -> ev.valid = true || (<expr>)
//
// This command is measurement tooling, not part of the consumer surface: nothing
// a relying party runs imports it, and it never touches a tree outside the one
// named by -pkg. scripts/forcing-gate.py drives it.
//
// Usage:
//
//	mutgen -pkg <dir> -list               # JSON-lines catalogue of every site
//	mutgen -pkg <dir> -apply <KEY>        # print the mutated file
//	mutgen -pkg <dir> -apply <KEY> -write # rewrite the one file in place
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns the process exit code: 0 on
// success, 2 on a usage error, an unparseable package, or a key that names no
// site.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mutgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pkg := fs.String("pkg", "", "package directory to enumerate or mutate")
	list := fs.Bool("list", false, "write every mutation site as one JSON object per line")
	applyKey := fs.String("apply", "", "apply the mutation with this site key")
	write := fs.Bool("write", false, "with -apply, rewrite the file in place instead of writing to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pkg == "" {
		fmt.Fprintln(stderr, "mutgen: -pkg is required")
		return 2
	}
	if *list == (*applyKey != "") {
		fmt.Fprintln(stderr, "mutgen: exactly one of -list and -apply is required")
		return 2
	}
	if *list {
		return runList(*pkg, stdout, stderr)
	}
	return runApply(*pkg, *applyKey, *write, stdout, stderr)
}

// sourceFiles lists the non-test Go files of a package directory, sorted.
func sourceFiles(pkg string) ([]string, error) {
	entries, err := os.ReadDir(pkg)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			files = append(files, n)
		}
	}
	sort.Strings(files)
	return files, nil
}

func parseOne(pkg, rel string) (*token.FileSet, *ast.File, error) {
	fset := token.NewFileSet()
	// #nosec G304 -- mutgen parses the package directory it was pointed at; it
	// is developer tooling over this repository's own source, not a verifier
	// reading untrusted bytes.
	f, err := parser.ParseFile(fset, filepath.Join(pkg, rel), nil, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}
	return fset, f, nil
}

func runList(pkg string, stdout, stderr io.Writer) int {
	files, err := sourceFiles(pkg)
	if err != nil {
		fmt.Fprintln(stderr, "mutgen:", err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	for _, rel := range files {
		fset, f, err := parseOne(pkg, rel)
		if err != nil {
			fmt.Fprintln(stderr, "mutgen:", err)
			return 2
		}
		for _, s := range collect(fset, f, rel) {
			if err := enc.Encode(s); err != nil {
				fmt.Fprintln(stderr, "mutgen:", err)
				return 2
			}
		}
	}
	return 0
}

func runApply(pkg, key string, write bool, stdout, stderr io.Writer) int {
	rel := fileOfKey(key)
	if rel == "" || !strings.HasSuffix(rel, ".go") {
		fmt.Fprintf(stderr, "mutgen: %q does not name a source file; a site key starts with <file>.go::\n", key)
		return 2
	}
	fset, f, err := parseOne(pkg, rel)
	if err != nil {
		fmt.Fprintln(stderr, "mutgen:", err)
		return 2
	}
	var found *site
	for _, s := range collect(fset, f, rel) {
		if s.Key == key {
			found = s
			break
		}
	}
	if found == nil {
		fmt.Fprintf(stderr, "mutgen: no site %s in %s\n", key, rel)
		return 2
	}
	if err := apply(f, found); err != nil {
		fmt.Fprintln(stderr, "mutgen:", err)
		return 2
	}
	// Synthesized nodes carry no position, so go/printer cannot place the
	// original comment groups reliably around them, and a deleted case clause can
	// strand a comment inside an expression. Comments cannot change what the
	// mutant computes, so they are dropped rather than risked.
	f.Comments = nil

	out := stdout
	if write {
		path := filepath.Join(pkg, rel)
		// #nosec G304 -- the path is derived from -pkg and the site key, both
		// supplied by the developer running this tool over their own checkout.
		fh, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(stderr, "mutgen:", err)
			return 2
		}
		defer func() { _ = fh.Close() }()
		out = fh
	}
	if err := printer.Fprint(out, fset, f); err != nil {
		fmt.Fprintln(stderr, "mutgen:", err)
		return 2
	}
	return 0
}
