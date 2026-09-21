//go:build darwin

package macos

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveProgramRemovesAppAndItsCLILink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	app := filepath.Join(home, "Applications", appName)
	executable := writeTestApp(t, app, bundleIdentifier, executableName)
	link := filepath.Join(home, ".local", "bin", "quesma-shipper")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	require.NoError(t, os.Symlink(executable, link))

	removed, err := RemoveProgram(executable)
	require.NoError(t, err)
	require.Equalf(t, app, removed, "removed path = %q, want %q", removed, app)
	for _, path := range []string{app, link} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s still exists: %v", path, err)
		}
	}
}

func TestRemoveProgramRefusesAnUnrelatedApp(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Other.app")
	executable := writeTestApp(t, app, "com.example.other", executableName)
	if _, err := RemoveProgram(executable); err == nil {
		t.Fatal("uninstall accepted an unrelated app")
	}
	if _, err := os.Stat(app); err != nil {
		t.Fatalf("uninstall damaged the unrelated app: %v", err)
	}
}
