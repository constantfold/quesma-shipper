//go:build darwin

package macos

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppForExecutableValidatesIdentity(t *testing.T) {
	app := filepath.Join(t.TempDir(), appName)
	executable := writeTestApp(t, app, bundleIdentifier, executableName)
	got, ok := appForExecutable(executable)
	require.True(t, ok)
	require.Equal(t, app, got)
	for name, exe := range map[string]string{
		"a raw binary":            "/Users/me/.local/bin/quesma-shipper",
		"an unrelated app":        writeTestApp(t, filepath.Join(t.TempDir(), "Other.app"), "com.example.other", executableName),
		"an unrelated executable": writeTestApp(t, filepath.Join(t.TempDir(), appName), bundleIdentifier, "helper"),
	} {
		_, ok := appForExecutable(exe)
		assert.False(t, ok, "%s was treated as Quesma Shipper", name)
	}
}

func TestApplyAppPackageReplacesTheWholeBundle(t *testing.T) {
	parent := t.TempDir()
	app := filepath.Join(parent, appName)
	require.NoError(t, os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(app, "old"), []byte("old"), 0o600))

	const version = "0.0.1-123.abcdef123456"
	require.NoError(t, applyAppPackage(testAppPackage(t, version), app, version))
	assert.NoFileExists(t, filepath.Join(app, "old"), "old bundle survived replacement")
	got, err := os.ReadFile(filepath.Join(app, "new"))
	require.NoError(t, err, "new bundle not installed")
	assert.Equal(t, "new", string(got))
}

// When CI points at the built package, the updater accepts its bundle and Installer lays that component out.
func TestBuiltPackageSatisfiesTheUpdater(t *testing.T) {
	pkg, version := os.Getenv("QUESMA_SHIPPER_PKG"), os.Getenv("QUESMA_SHIPPER_RELEASE_VERSION")
	if pkg == "" || version == "" {
		t.Skip("set QUESMA_SHIPPER_PKG and QUESMA_SHIPPER_RELEASE_VERSION to check a built package")
	}
	raw, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, err = expandAppPackage(raw, t.TempDir(), version)
	require.NoError(t, err, "the updater rejects the built package")
	selected := installerChoices(t, pkg)
	require.Truef(t, selected[bundleIdentifier], "Installer choice selection = %v; %s must be laid out", selected, bundleIdentifier)
}

// installerChoices reads Installer's own view of what the package would lay out.
func installerChoices(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	show := exec.Command("/usr/sbin/installer", "-showChoicesXML", "-pkg", pkg, "-target", "CurrentUserHomeDirectory")
	convert := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	xml, err := show.Output()
	require.NoError(t, err, "installer -showChoicesXML")
	convert.Stdin = strings.NewReader(string(xml))
	out, err := convert.Output()
	require.NoError(t, err, "plutil -convert json")
	var choices []installerChoice
	require.NoError(t, json.Unmarshal(out, &choices))
	selected := map[string]bool{}
	var walk func([]installerChoice)
	walk = func(cs []installerChoice) {
		for _, c := range cs {
			// Only leaves carry a package; a group reports -1 for a mixed selection.
			if len(c.Children) == 0 {
				selected[c.Identifier] = c.Selected == 1
			}
			walk(c.Children)
		}
	}
	walk(choices)
	return selected
}

type installerChoice struct {
	Identifier string            `json:"choiceIdentifier"`
	Selected   int               `json:"choiceIsSelected"`
	Children   []installerChoice `json:"childItems"`
}

// testAppPackage builds a product archive holding the component the updater expects.
func testAppPackage(t *testing.T, version string) []byte {
	t.Helper()
	root := t.TempDir()
	app := filepath.Join(root, "Applications", appName)
	writeTestBundle(t, app, version)
	require.NoError(t, os.WriteFile(filepath.Join(app, "new"), []byte("new"), 0o644))

	work := t.TempDir()
	component := filepath.Join(work, componentPackage)
	out, err := exec.Command("/usr/bin/pkgbuild", "--root", root, "--identifier", bundleIdentifier, "--version", "1", component).CombinedOutput()
	require.NoErrorf(t, err, "pkgbuild: %s", out)
	pkg := filepath.Join(work, "quesma-shipper.pkg")
	out, err = exec.Command("/usr/bin/productbuild", "--package", component, pkg).CombinedOutput()
	require.NoErrorf(t, err, "productbuild: %s", out)
	raw, err := os.ReadFile(pkg)
	require.NoError(t, err)
	return raw
}

// writeTestBundle is writeTestApp plus the release-version key the updater validates.
func writeTestBundle(t *testing.T, app, version string) {
	t.Helper()
	writeTestApp(t, app, bundleIdentifier, executableName)
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + bundleIdentifier + `</string>
<key>` + releaseVersionField + `</key><string>` + version + `</string>
</dict></plist>`
	require.NoError(t, os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644))
}

func writeTestApp(t *testing.T, app, bundleID, executableName string) string {
	t.Helper()
	executable := filepath.Join(app, "Contents", "MacOS", executableName)
	require.NoError(t, os.MkdirAll(filepath.Dir(executable), 0o755))
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + bundleID + `</string></dict></plist>`
	require.NoError(t, os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644))
	require.NoError(t, os.WriteFile(executable, []byte("binary"), 0o755))
	return executable
}
