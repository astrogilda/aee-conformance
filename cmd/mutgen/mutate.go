package main

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"sort"
	"strings"
)

// site is one weakening mutation: a single syntactic place in the rail that can
// be switched off, plus the identity under which the forcing baseline records
// what happened when it was.
type site struct {
	Key     string `json:"key"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Func    string `json:"func"`
	Op      string `json:"op"`
	Snippet string `json:"snippet"`

	// Set during enumeration, used by apply. Never serialized.
	target  ast.Expr
	replace string
	kind    string
	call    *ast.CallExpr
	assign  *ast.AssignStmt
	ret     *ast.ReturnStmt
	clause  *ast.CaseClause
	swBody  *ast.BlockStmt
}

// maxSnippet bounds the recorded source excerpt. It is part of the site key, so
// two sites whose first maxSnippet characters agree collide and are separated by
// the occurrence ordinal instead.
const maxSnippet = 150

// keyDigestBytes is how much of the snippet digest goes into a key. Twelve hex
// characters is enough to separate the sites within one function without making
// the baseline unreadable; a collision is not a correctness problem because the
// ordinal disambiguates every group that shares a key.
const keyDigestBytes = 6

// siteKey names a mutation site by WHAT IT IS rather than by where it sits.
//
// The obvious identity -- an ordinal per file, `statement#013` -- renumbers every
// site below any inserted rule, so a one-line addition to the rail would read as
// several hundred simultaneous forcing regressions and the baseline would have to
// be regenerated wholesale on every edit, which is the same as having no ratchet.
// Keying on (file, function, operator, digest of the mutated source) instead moves
// with the code: a site keeps its identity when lines shift around it, and loses
// it exactly when the rule it guards is rewritten, which is the case a reviewer
// should be made to look at.
//
// ordinal separates sites that are otherwise identical -- the same operator on the
// same expression twice inside one function, which `if err != nil { return err }`
// produces constantly. It is assigned in source order, so adding a third copy
// leaves the first two alone.
func siteKey(file, fn, op, snippet string, ordinal int) string {
	sum := sha256.Sum256([]byte(snippet))
	key := fmt.Sprintf("%s::%s::%s::%x", file, fn, op, sum[:keyDigestBytes])
	if ordinal > 1 {
		key = fmt.Sprintf("%s#%d", key, ordinal)
	}
	return key
}

// fileOfKey recovers the source file a key names, so -apply needs only the key.
func fileOfKey(key string) string {
	return strings.SplitN(key, "::", 2)[0]
}

// shortCircuit builds `false && (e)` or `true || (e)`.
//
// The literal `false` alone would be the obvious rewrite and it is wrong: it
// deletes the last use of whatever the guard read, Go then refuses to compile a
// declared-and-unused variable, and the mutant scores as inconclusive instead of
// as the measurement it was supposed to be. Keeping the original expression
// behind a short-circuit forces the branch while leaving every identifier used.
func shortCircuit(e ast.Expr, lit string) ast.Expr {
	op := token.LAND
	if lit == "true" {
		op = token.LOR
	}
	return &ast.BinaryExpr{
		X:  ast.NewIdent(lit),
		Op: op,
		Y:  &ast.ParenExpr{X: e},
	}
}

// suppressCode rewrites appendCode(cs, C) to an immediately-invoked function
// returning cs and discarding C, so one emission disappears while both arguments
// stay referenced.
func suppressCode(call *ast.CallExpr) ast.Expr {
	return &ast.CallExpr{
		Fun: &ast.FuncLit{
			Type: &ast.FuncType{
				Params: &ast.FieldList{List: []*ast.Field{
					{Names: []*ast.Ident{ast.NewIdent("cs")}, Type: &ast.ArrayType{Elt: ast.NewIdent("Code")}},
					{Names: []*ast.Ident{ast.NewIdent("_")}, Type: ast.NewIdent("Code")},
				}},
				Results: &ast.FieldList{List: []*ast.Field{
					{Type: &ast.ArrayType{Elt: ast.NewIdent("Code")}},
				}},
			},
			Body: &ast.BlockStmt{List: []ast.Stmt{
				&ast.ReturnStmt{Results: []ast.Expr{ast.NewIdent("cs")}},
			}},
		},
		Args: []ast.Expr{call.Args[0], call.Args[1]},
	}
}

// flatten returns the leaf operands of a left-associated binary chain of op.
func flatten(e ast.Expr, op token.Token) []ast.Expr {
	be, ok := e.(*ast.BinaryExpr)
	if !ok || be.Op != op {
		return []ast.Expr{e}
	}
	return append(flatten(be.X, op), flatten(be.Y, op)...)
}

// srcOf renders a node as one whitespace-collapsed line, bounded by maxSnippet.
func srcOf(fset *token.FileSet, n ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, n); err != nil {
		return "<unprintable>"
	}
	s := strings.Join(strings.Fields(sb.String()), " ")
	if len(s) > maxSnippet {
		s = s[:maxSnippet] + "..."
	}
	return s
}

type funcRange struct {
	name       string
	start, end token.Pos
}

// funcIndex maps a position to the name of the function declaration holding it,
// and reports whether that declaration returns exactly one bool (whose return
// statements are sub-check arms worth mutating).
type funcIndex struct {
	ranges []funcRange
	bools  []funcRange
}

func newFuncIndex(f *ast.File) *funcIndex {
	idx := &funcIndex{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = "(recv)." + name
		}
		fr := funcRange{name, fd.Pos(), fd.End()}
		idx.ranges = append(idx.ranges, fr)
		if returnsOneBool(fd) {
			idx.bools = append(idx.bools, fr)
		}
	}
	return idx
}

func returnsOneBool(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil || len(fd.Type.Results.List) != 1 {
		return false
	}
	if len(fd.Type.Results.List[0].Names) > 1 {
		return false
	}
	id, ok := fd.Type.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "bool"
}

func (i *funcIndex) nameAt(p token.Pos) string {
	for _, fr := range i.ranges {
		if p >= fr.start && p < fr.end {
			return fr.name
		}
	}
	return "-"
}

func (i *funcIndex) inBoolFunc(p token.Pos) bool {
	for _, fr := range i.bools {
		if p >= fr.start && p < fr.end {
			return true
		}
	}
	return false
}

// taggedClauses records the case clauses of TAGGED and TYPE switches. Their case
// lists carry values and types rather than booleans, so `case false && (v):` does
// not typecheck and `case json.Delim:` does not even parse as an expression; the
// equivalent weakening there is to delete the arm and let its value fall through.
func taggedClauses(f *ast.File) map[*ast.CaseClause]*ast.BlockStmt {
	out := map[*ast.CaseClause]*ast.BlockStmt{}
	ast.Inspect(f, func(nd ast.Node) bool {
		var body *ast.BlockStmt
		switch sw := nd.(type) {
		case *ast.SwitchStmt:
			if sw.Tag == nil {
				return true
			}
			body = sw.Body
		case *ast.TypeSwitchStmt:
			body = sw.Body
		default:
			return true
		}
		for _, st := range body.List {
			if cc, ok := st.(*ast.CaseClause); ok && len(cc.List) > 0 {
				out[cc] = body
			}
		}
		return true
	})
	return out
}

func isLit(e ast.Expr, want string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == want
}

// collector accumulates the sites of one file.
type collector struct {
	fset  *token.FileSet
	rel   string
	funcs *funcIndex
	out   []*site
}

func (c *collector) add(op string, node ast.Node, s *site) {
	s.File = c.rel
	s.Line = c.fset.Position(node.Pos()).Line
	s.Func = c.funcs.nameAt(node.Pos())
	s.Op = op
	s.Snippet = srcOf(c.fset, node)
	c.out = append(c.out, s)
}

// condSites enumerates the three weakenings of one boolean guard: the whole
// guard off, each disjunct off, each conjunct off.
func (c *collector) condSites(prefix string, cond ast.Expr, owner ast.Node) {
	if !isLit(cond, "false") {
		c.add(prefix+"_OFF", owner, &site{kind: "expr", target: cond, replace: "false"})
	}
	if or := flatten(cond, token.LOR); len(or) > 1 {
		for _, leaf := range or {
			if isLit(leaf, "false") {
				continue
			}
			c.add(prefix+"_DISJ", leaf, &site{kind: "expr", target: leaf, replace: "false"})
		}
	}
	if and := flatten(cond, token.LAND); len(and) > 1 {
		for _, leaf := range and {
			if isLit(leaf, "true") {
				continue
			}
			c.add(prefix+"_CONJ", leaf, &site{kind: "expr", target: leaf, replace: "true"})
		}
	}
}

// collect enumerates every weakening mutation site in one parsed file, in source
// order, with keys already assigned.
func collect(fset *token.FileSet, f *ast.File, rel string) []*site {
	c := &collector{fset: fset, rel: rel, funcs: newFuncIndex(f)}
	tagged := taggedClauses(f)

	ast.Inspect(f, func(nd ast.Node) bool {
		switch x := nd.(type) {
		case *ast.IfStmt:
			if x.Cond != nil {
				c.condSites("IF", x.Cond, x)
			}
		case *ast.CaseClause:
			if body, isTagged := tagged[x]; isTagged {
				c.add("CASE_DEL", x, &site{kind: "casedel", clause: x, swBody: body})
				break
			}
			for _, e := range x.List {
				c.condSites("CASE", e, e)
			}
		case *ast.ReturnStmt:
			if c.funcs.inBoolFunc(x.Pos()) && len(x.Results) == 1 {
				if !isLit(x.Results[0], "true") {
					c.add("RET_TRUE", x, &site{kind: "ret", ret: x, replace: "true"})
				}
				if !isLit(x.Results[0], "false") {
					c.add("RET_FALSE", x, &site{kind: "ret", ret: x, replace: "false"})
				}
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "appendCode" && len(x.Args) == 2 {
				c.add("CODE_OFF", x, &site{kind: "call", call: x})
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
				if se, ok := x.Lhs[0].(*ast.SelectorExpr); ok && se.Sel.Name == "valid" {
					if !isLit(x.Rhs[0], "true") {
						c.add("VALID_TRUE", x, &site{kind: "assign", assign: x, replace: "true"})
					}
				}
			}
		}
		return true
	})

	sort.SliceStable(c.out, func(i, j int) bool { return c.out[i].Line < c.out[j].Line })
	assignKeys(c.out)
	return c.out
}

// assignKeys gives every site its stable key, numbering repeated keys in source
// order.
func assignKeys(sites []*site) {
	seen := map[string]int{}
	for _, s := range sites {
		base := siteKey(s.File, s.Func, s.Op, s.Snippet, 1)
		seen[base]++
		s.Key = siteKey(s.File, s.Func, s.Op, s.Snippet, seen[base])
	}
}

// apply performs one mutation by rewriting the AST in place.
func apply(f *ast.File, s *site) error {
	done := false
	switch s.kind {
	case "expr":
		replaceExpr(f, s.target, shortCircuit(s.target, s.replace), &done)
	case "ret":
		s.ret.Results[0] = shortCircuit(s.ret.Results[0], s.replace)
		done = true
	case "call":
		replaceExpr(f, s.call, suppressCode(s.call), &done)
	case "assign":
		s.assign.Rhs[0] = shortCircuit(s.assign.Rhs[0], s.replace)
		done = true
	case "casedel":
		var kept []ast.Stmt
		for _, st := range s.swBody.List {
			if st == ast.Stmt(s.clause) {
				done = true
				continue
			}
			kept = append(kept, st)
		}
		s.swBody.List = kept
	}
	if !done {
		return fmt.Errorf("mutation site %s not reachable in AST", s.Key)
	}
	return nil
}

// replaceExpr walks the file replacing the exact node pointer old with nw.
//
// One arm per expression-bearing parent node. The branch count is the node
// count: a table keyed on reflect.Type would be shorter and would hide which
// parents are covered, and a parent that is silently absent is a mutation that
// reports success and changes nothing, which scores as a measurement that was
// never taken. The accepted-complexity table records this.
func replaceExpr(root ast.Node, old, nw ast.Expr, done *bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		if *done || n == nil {
			return !*done
		}
		switch x := n.(type) {
		case *ast.IfStmt:
			if x.Cond == old {
				x.Cond = nw
				*done = true
			}
		case *ast.BinaryExpr:
			if x.X == old {
				x.X = nw
				*done = true
			} else if x.Y == old {
				x.Y = nw
				*done = true
			}
		case *ast.UnaryExpr:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.ParenExpr:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.CaseClause:
			for i := range x.List {
				if x.List[i] == old {
					x.List[i] = nw
					*done = true
				}
			}
		case *ast.AssignStmt:
			for i := range x.Rhs {
				if x.Rhs[i] == old {
					x.Rhs[i] = nw
					*done = true
				}
			}
		case *ast.ReturnStmt:
			for i := range x.Results {
				if x.Results[i] == old {
					x.Results[i] = nw
					*done = true
				}
			}
		case *ast.CallExpr:
			if x.Fun == old {
				x.Fun = nw
				*done = true
			}
			for i := range x.Args {
				if x.Args[i] == old {
					x.Args[i] = nw
					*done = true
				}
			}
		case *ast.ExprStmt:
			if x.X == old {
				x.X = nw
				*done = true
			}
		case *ast.KeyValueExpr:
			if x.Value == old {
				x.Value = nw
				*done = true
			}
		case *ast.ForStmt:
			if x.Cond == old {
				x.Cond = nw
				*done = true
			}
		case *ast.SwitchStmt:
			if x.Tag == old {
				x.Tag = nw
				*done = true
			}
		case *ast.IndexExpr:
			if x.Index == old {
				x.Index = nw
				*done = true
			}
		}
		return !*done
	})
}
