//go:build darwin

package macos

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppForExecutableValidatesIdentity(t *testing.T) {
	app := filepath.Join(t.TempDir(), appName)
	executable := writeTestApp(t, app, bundleIdentifier, executableName)
	if got, ok := appForExecutable(executable); !ok || got != app {
		t.Fatalf("appForExecutable() = %q, %v", got, ok)
	}
	if _, ok := appForExecutable("/Users/me/.local/bin/quesma-shipper"); ok {
		t.Fatal("a raw binary was treated as an app bundle")
	}
	other := filepath.Join(t.TempDir(), "Other.app")
	if _, ok := appForExecutable(writeTestApp(t, other, "com.example.other", executableName)); ok {
		t.Fatal("an unrelated app was treated as Quesma Shipper")
	}
	wrongName := filepath.Join(t.TempDir(), appName)
	if _, ok := appForExecutable(writeTestApp(t, wrongName, bundleIdentifier, "helper")); ok {
		t.Fatal("an unrelated executable was treated as Quesma Shipper")
	}
}

func TestApplyAppPackageReplacesTheWholeBundle(t *testing.T) {
	parent := t.TempDir()
	app := filepath.Join(parent, appName)
	require.NoError(t, os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(app, "old"), []byte("old"), 0o600))

	const version = "0.0.1-123.abcdef123456"
	require.NoError(t, applyAppPackage(testAppPackage(t, version), app, version))
	if _, err := os.Stat(filepath.Join(app, "old")); !os.IsNotExist(err) {
		t.Fatalf("old bundle survived replacement: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(app, "new")); err != nil || string(got) != "new" {
		t.Fatalf("new bundle not installed: %q, %v", got, err)
	}
}

// When CI points at the built package, the updater accepts its bundle and Installer lays that component out.
func TestBuiltPackageSatisfiesTheUpdater(t *testing.T) {
	pkg, version := os.Getenv("QUESMA_SHIPPER_PKG"), os.Getenv("QUESMA_SHIPPER_RELEASE_VERSION")
	if pkg == "" || version == "" {
		t.Skip("set QUESMA_SHIPPER_PKG and QUESMA_SHIPPER_RELEASE_VERSION to check a built package")
	}
	raw, err := os.ReadFile(pkg)
	require.NoError(t, err)
	_, expandAppPackageErr := expandAppPackage(raw, t.TempDir(), version)
	require.NoErrorf(t, expandAppPackageErr, "the updater rejects the built package: %v", expandAppPackageErr)
	if selected := installerChoices(t, pkg); !selected[bundleIdentifier] {
		t.Fatalf("Installer choice selection = %v; %s must be laid out", selected, bundleIdentifier)
	}
}

// installerChoices reads Installer's own view of what the package would lay out.
func installerChoices(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	show := exec.Command("/usr/sbin/installer", "-showChoicesXML", "-pkg", pkg, "-target", "CurrentUserHomeDirectory")
	convert := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	xml, err := show.Output()
	require.NoErrorf(t, err, "installer -showChoicesXML: %v", err)
	convert.Stdin = strings.NewReader(string(xml))
	out, err := convert.Output()
	require.NoErrorf(t, err, "plutil -convert json: %v", err)
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
	if res, err := exec.Command("/usr/bin/pkgbuild", "--root", root, "--identifier", bundleIdentifier,
		"--version", "1", component).CombinedOutput(); err != nil {
		t.Fatalf("pkgbuild: %v: %s", err, res)
	}
	pkg := filepath.Join(work, "quesma-shipper.pkg")
	if out, err := exec.Command("/usr/bin/productbuild", "--package", component, pkg).CombinedOutput(); err != nil {
		t.Fatalf("productbuild: %v: %s", err, out)
	}
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
