package platform_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moduleRoot is derived rather than a hardcoded relative depth, which a directory move silently misdirects.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no go.mod above the test's working directory")
		dir = parent
	}
}

// forEachModuleGoFile parses every non-test .go file in the module, skipping generated trees and
// nested modules, and hands each to fn. It is the shared walk behind the module-wide lints here.
func forEachModuleGoFile(t *testing.T, fn func(rel string, file *ast.File, fset *token.FileSet)) {
	t.Helper()
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "conformance", ".git":
				return fs.SkipDir
			}
			// A nested module is not in this module, the same boundary go list draws.
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(rel), file, fset)
		return nil
	})
	require.NoError(t, err)
}

// writeCapablePackages may open files for writing; everything else must route through safeio,
// which is what keeps "the shipper never writes inside an agent's store" true. Each entry owns a
// specific durable artifact. sqliteread weakens this lint, so it carries a compensating control: it
// may write only under the scratch directory it is given, asserted by TestDeclaredReadContract.
var writeCapablePackages = []string{
	"internal/platform/auditlog",     // the append-only local log
	"internal/platform/crashjournal", // the append-only crash journal
	"internal/sources/sqliteread",    // scratch snapshots and cold copies of agent databases
	"packaging/macos",                // the app bundle and the LaunchAgent
	"packaging/linux",                // the systemd unit
	"packaging/windows",              // the scheduled task definition
}

// writeCapableFiles is the file-granular half, for merged packages: a directory grant to platform
// would extend write rights to memstat and buildinfo, which have none and must stay that way.
var writeCapableFiles = []string{
	"internal/platform/safeio.go",    // the sanctioned write path itself
	"internal/platform/pause.go",     // the pause flag
	"internal/engine/state.go",       // the fingerprint document
	"internal/sources/ignore.go",     // the .notrajectories repository marker
	"packaging/common/service.go",    // service state
	"packaging/common/remove.go",     // the installed standalone executable
	"packaging/common/selfupdate.go", // the self-update hop guard
}

// bannedWrites are the os-level calls that create or truncate a file.
var bannedWrites = map[string]string{
	"Create":     "os.Create truncates and is not atomic",
	"WriteFile":  "os.WriteFile is not atomic: a crash mid-write leaves a torn file",
	"Mkdir":      "directory creation belongs with the artifact's owner",
	"MkdirAll":   "directory creation belongs with the artifact's owner",
	"Remove":     "deletion of local state belongs with the artifact's owner",
	"RemoveAll":  "deletion of local state belongs with the artifact's owner",
	"Rename":     "the atomic-rename commit point lives in safeio",
	"Truncate":   "truncation is never correct on a store the shipper reads",
	"Chmod":      "mode changes belong with the artifact's owner",
	"Symlink":    "the shipper never creates links",
	"Link":       "the shipper never creates links",
	"OpenFile":   "os.OpenFile can open for writing; use safeio",
	"CreateTemp": "temp files are safeio's business, so the suffix stays consistent",
}

// TestWritePathLint fails if a package outside the allow-list opens a file for writing: a lint, because Go cannot forbid an import.
func TestWritePathLint(t *testing.T) {
	var findings []string
	forEachModuleGoFile(t, func(rel string, file *ast.File, fset *token.FileSet) {
		if slices.Contains(writeCapablePackages, filepath.ToSlash(filepath.Dir(rel))) {
			return
		}
		if slices.Contains(writeCapableFiles, rel) {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "os" {
				return true
			}
			why, banned := bannedWrites[sel.Sel.Name]
			if !banned {
				return true
			}
			findings = append(findings, fmt.Sprintf("%s:%d: os.%s outside the write allow-list — %s",
				rel, fset.Position(call.Pos()).Line, sel.Sel.Name, why))
			return true
		})
	})

	for _, f := range findings {
		t.Error(f)
	}
	if len(findings) > 0 {
		t.Logf("packages permitted to write: %s", strings.Join(writeCapablePackages, ", "))
	}
}

// bannedExec are the calls that create a process. os/exec wraps os.StartProcess, so its import is
// banned outright; syscall's process spawners are named directly.
var bannedExec = map[string]map[string]bool{"os": {"StartProcess": true}, "syscall": {"Exec": true, "ForkExec": true}}

// TestNoExecOutsidePackaging: os/exec reads as malware to an auditor, so the collector's data path
// only permits packaging processes and the macOS Keychain reader.
func TestNoExecOutsidePackaging(t *testing.T) {
	forEachModuleGoFile(t, func(rel string, file *ast.File, fset *token.FileSet) {
		if rel == "packaging" || strings.HasPrefix(rel, "packaging/") || rel == "internal/sources/accounts_keychain_darwin.go" {
			return
		}
		for _, imp := range file.Imports {
			assert.NotEqual(t, `"os/exec"`, imp.Path.Value)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && bannedExec[pkg.Name][sel.Sel.Name] {
				t.Errorf("%s:%d: calls %s.%s: process creation is allowed only under packaging/ or in the macOS Keychain reader",
					rel, fset.Position(sel.Pos()).Line, pkg.Name, sel.Sel.Name)
			}
			return true
		})
	})
}
