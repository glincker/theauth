// Command route-manifest scans a theauth-go checkout for chi route
// registrations and prints them as JSON. It imports nothing from that repo.
//
//	go run . -dir /path/to/theauth-go -commit "$(git -C /path/to/theauth-go rev-parse HEAD)" > routes.generated.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type manifest struct {
	Source map[string]string `json:"source"`
	Routes []route           `json:"routes"`
}

var verbs = map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE"}

func main() {
	dir := flag.String("dir", ".", "theauth-go checkout")
	commit := flag.String("commit", "", "source commit recorded in the output")
	mount := flag.String("mount", "/auth", "prefix the scanned routers are mounted under")
	flag.Parse()

	files, err := goFiles(*dir)
	if err != nil {
		fail(err)
	}
	seen := map[route]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		tree, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			fail(err)
		}
		walk(tree, "", *mount, seen)
	}
	out := make([]route, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(manifest{Source: map[string]string{"repo": "theauth-go", "commit": *commit, "mount": *mount}, Routes: out})
}

func goFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "examples" || d.Name() == "docs-site") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// walk follows nested r.Route("/x", func(r chi.Router) {...}) literals so a
// route inside one inherits its prefix. Routers mounted from other functions
// all hang off the single mount prefix, which is how theauth-go wires them.
func walk(n ast.Node, prefix, mount string, seen map[route]bool) {
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if name == "Route" && len(call.Args) == 2 {
			if lit, ok := call.Args[1].(*ast.FuncLit); ok {
				if p, ok := stringArg(call.Args[0]); ok {
					walk(lit.Body, prefix+p, mount, seen)
					return false
				}
			}
			return true
		}
		if verb, ok := verbs[name]; ok && len(call.Args) >= 1 {
			if p, ok := stringArg(call.Args[0]); ok && strings.HasPrefix(p, "/") {
				seen[route{Method: verb, Path: mount + prefix + p}] = true
			}
		}
		return true
	})
}

func stringArg(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
