package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A dynamic reflect.Value.MethodByName keeps every exported method alive (9 MB once, via cobra
// templates); the linker tags it <ReflectMethod> in -dumpdep.
func TestNoDynamicMethodByName(t *testing.T) {
	build := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "quesma-shipper"), "-ldflags=-dumpdep", ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoErrorf(t, err, "go build: %v\n%s", err, out)
	for _, line := range strings.Split(string(out), "\n") {
		assert.NotContainsf(t, line, "<ReflectMethod>", "linker dead-code elimination is off, reached via: %s", line)
	}
}
