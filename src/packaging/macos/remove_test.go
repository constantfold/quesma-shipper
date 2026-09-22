//go:build darwin

package macos

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
	require.Equal(t, app, removed)
	assert.NoDirExists(t, app)
	assert.NoFileExists(t, link)
}

func TestRemoveProgramRefusesAnUnrelatedApp(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Other.app")
	executable := writeTestApp(t, app, "com.example.other", executableName)
	_, err := RemoveProgram(executable)
	require.Error(t, err, "uninstall accepted an unrelated app")
	require.DirExists(t, app, "uninstall damaged the unrelated app")
}
