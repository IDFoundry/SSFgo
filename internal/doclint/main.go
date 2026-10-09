// Command doclint reports exported identifiers of the public packages that
// have no doc comment: declarations, and the fields of exported structs
// (design rule 14). CI runs it as go run ./internal/doclint; it prints each
// one and exits non-zero if there are any.
//
// A declaration in a group — const (...) or var (...) — is covered by the
// group's comment; a field by a comment above it or at the end of its line.
// Test files, internal packages, commands and examples are not checked.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	missing, err := check(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "doclint:", err)
		os.Exit(2)
	}
	for _, m := range missing {
		fmt.Println(m)
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "doclint: %d exported identifiers have no doc comment\n", len(missing))
		os.Exit(1)
	}
}

// skipped are directories whose packages are not public API.
var skipped = map[string]bool{"internal": true, "cmd": true, "examples": true, "testdata": true, "conformance": true, "interoptest": true}

// check returns "file:line: name" for each undocumented exported
// identifier under root, in order.
func check(root string) ([]string, error) {
	var missing []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (skipped[name] || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		if f.Name.Name == "main" {
			return nil
		}
		for _, decl := range f.Decls {
			missing = append(missing, undocumented(fset, decl)...)
		}
		return nil
	})
	sort.Strings(missing)
	return missing, err
}

// undocumented returns "file:line: name" for each exported identifier
// decl declares without a doc comment.
func undocumented(fset *token.FileSet, decl ast.Decl) []string {
	var names []ident
	switch d := decl.(type) {
	case *ast.FuncDecl:
		names = undocumentedFunc(d)
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			names = append(names, undocumentedSpec(d, spec)...)
		}
	}
	missing := make([]string, len(names))
	for i, n := range names {
		p := fset.Position(n.pos)
		missing[i] = fmt.Sprintf("%s:%d: %s", p.Filename, p.Line, n.name)
	}
	return missing
}

// ident is an undocumented identifier and where it is declared.
type ident struct {
	pos  token.Pos
	name string
}

// undocumentedFunc reports an exported function, or a method of an
// exported type, with no doc comment.
func undocumentedFunc(d *ast.FuncDecl) []ident {
	if !d.Name.IsExported() || (d.Recv != nil && !exportedReceiver(d.Recv)) || d.Doc != nil {
		return nil
	}
	return []ident{{d.Pos(), d.Name.Name}}
}

// undocumentedSpec reports the exported names in spec, a type or value of
// declaration d, with no doc comment of their own or d's.
func undocumentedSpec(d *ast.GenDecl, spec ast.Spec) []ident {
	var names []ident
	switch s := spec.(type) {
	case *ast.TypeSpec:
		names = undocumentedType(d, s)
	case *ast.ValueSpec:
		if s.Doc != nil || s.Comment != nil || d.Doc != nil {
			return nil
		}
		for _, n := range s.Names {
			if n.IsExported() {
				names = append(names, ident{n.Pos(), n.Name})
			}
		}
	}
	return names
}

// undocumentedType reports an exported type with no doc comment of its
// own or d's, and its undocumented exported fields if it is a struct.
func undocumentedType(d *ast.GenDecl, s *ast.TypeSpec) []ident {
	if !s.Name.IsExported() {
		return nil
	}
	var names []ident
	if s.Doc == nil && d.Doc == nil {
		names = append(names, ident{s.Pos(), s.Name.Name})
	}
	if st, ok := s.Type.(*ast.StructType); ok {
		names = append(names, undocumentedFields(s.Name.Name, st)...)
	}
	return names
}

// undocumentedFields reports the exported fields of struct typeName with
// no comment above them or at the end of their line.
func undocumentedFields(typeName string, st *ast.StructType) []ident {
	var names []ident
	for _, f := range st.Fields.List {
		if f.Doc != nil || f.Comment != nil {
			continue
		}
		for _, n := range f.Names {
			if n.IsExported() {
				names = append(names, ident{n.Pos(), typeName + "." + n.Name})
			}
		}
	}
	return names
}

// exportedReceiver reports whether a method's receiver type is exported.
func exportedReceiver(recv *ast.FieldList) bool {
	t := recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if idx, ok := t.(*ast.IndexExpr); ok {
		t = idx.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.IsExported()
}
