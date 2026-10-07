// Command doccheck builds the Go code in the documentation, so it cannot
// drift from the API it describes.
//
// Each harness in internal/doccheck/harness is a Go program with markers
// of the form
//
//	// SNIPPETS <file.md> "<heading>"
//
// on a line of their own. doccheck replaces each marker with the ```go
// blocks of that section of the file — from the heading to the next
// heading of the same or a higher level — in document order, writes each
// program to its own module built against this checkout, and vets it.
// Stubs in a harness stand in for what a document marks as the
// application's own. Every ```go block in GETTING_STARTED.md and
// docs/guides must be covered by a marker.
//
// Run it from the repository root:
//
//	go run ./internal/doccheck
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	marker  = regexp.MustCompile(`(?m)^[ \t]*// SNIPPETS (\S+) ("[^"]*")[ \t]*$`)
	goBlock = regexp.MustCompile("(?ms)^```go\n(.*?)^```")
	heading = regexp.MustCompile(`(?m)^(#+) .*$`)
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "doccheck:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	harnesses, err := filepath.Glob(filepath.Join(root, "internal/doccheck/harness/*.go.tmpl"))
	if err != nil || len(harnesses) == 0 {
		return fmt.Errorf("no harnesses in internal/doccheck/harness: %v", err)
	}
	repo := os.DirFS(root)
	covered := map[string]bool{} // "file.md:offset" of each block a marker covers
	var errs []error
	for _, h := range harnesses {
		if err := check(root, repo, h, covered); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(h), err))
		}
	}
	docs, _ := filepath.Glob(filepath.Join(root, "docs/guides/*.md"))
	docs = append(docs, filepath.Join(root, "GETTING_STARTED.md"))
	for _, doc := range docs {
		rel, _ := filepath.Rel(root, doc)
		src, err := fs.ReadFile(repo, rel)
		if err != nil {
			return err
		}
		for _, m := range goBlock.FindAllIndex(src, -1) {
			if !covered[rel+":"+strconv.Itoa(m[0])] {
				line := bytes.Count(src[:m[0]], []byte("\n")) + 1
				errs = append(errs, fmt.Errorf("%s:%d: a go block no harness checks", rel, line))
			}
		}
	}
	return errors.Join(errs...)
}

// check expands harness h and vets it, recording the blocks it covers.
func check(root string, repo fs.FS, h string, covered map[string]bool) error {
	rel, _ := filepath.Rel(root, h)
	tmpl, err := fs.ReadFile(repo, rel)
	if err != nil {
		return err
	}
	var expandErr error
	prog := marker.ReplaceAllFunc(tmpl, func(m []byte) []byte {
		sub := marker.FindSubmatch(m)
		file := string(sub[1])
		title, _ := strconv.Unquote(string(sub[2]))
		code, err := section(repo, file, title, covered)
		if err != nil {
			expandErr = errors.Join(expandErr, err)
		}
		return code
	})
	if expandErr != nil {
		return expandErr
	}
	dir, err := os.MkdirTemp("", "doccheck")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	gomod := fmt.Sprintf(`module doccheck

go 1.26.6

require (
	github.com/idfoundry/ssfgo v0.0.0-00010101000000-000000000000
	github.com/idfoundry/ssfgo/storage/sqlstore v0.0.0-00010101000000-000000000000
)

replace github.com/idfoundry/ssfgo => %s

replace github.com/idfoundry/ssfgo/storage/sqlstore => %s
`, root, filepath.Join(root, "storage/sqlstore"))
	sum, _ := fs.ReadFile(repo, "storage/sqlstore/go.sum")
	for name, data := range map[string][]byte{"main.go": prog, "go.mod": []byte(gomod), "go.sum": sum} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	for _, cmd := range []*exec.Cmd{exec.Command("go", "mod", "tidy"), exec.Command("go", "vet", ".")} {
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w\n%s\nexpanded program:\n%s", strings.Join(cmd.Args, " "), err, out, numbered(prog))
		}
	}
	return nil
}

// section returns the go blocks of the section of file titled title — the
// whole file if title is empty — recording each as covered.
func section(repo fs.FS, file, title string, covered map[string]bool) ([]byte, error) {
	src, err := fs.ReadFile(repo, file)
	if err != nil {
		return nil, err
	}
	start, end := 0, len(src)
	if title != "" {
		hs := heading.FindAllSubmatchIndex(src, -1)
		i := slices.IndexFunc(hs, func(h []int) bool { return string(src[h[0]:h[1]]) == title })
		if i < 0 {
			return nil, fmt.Errorf("%s has no heading %q", file, title)
		}
		level := hs[i][3] - hs[i][2]
		start = hs[i][1]
		for _, h := range hs[i+1:] {
			if h[3]-h[2] <= level {
				end = h[0]
				break
			}
		}
	}
	var code []byte
	for _, m := range goBlock.FindAllSubmatchIndex(src[start:end], -1) {
		covered[file+":"+strconv.Itoa(start+m[0])] = true
		code = append(code, src[start+m[2]:start+m[3]]...)
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("%s %q has no go blocks", file, title)
	}
	return code, nil
}

func numbered(src []byte) string {
	var b strings.Builder
	for i, line := range strings.Split(string(src), "\n") {
		fmt.Fprintf(&b, "%4d  %s\n", i+1, line)
	}
	return b.String()
}
