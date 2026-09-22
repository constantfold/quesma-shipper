//go:build darwin

package macos

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

// UpdateTarget prefers the signed package when this binary runs from the app bundle.
func UpdateTarget(release common.Release) string {
	if _, ok := currentAppBundle(); ok {
		return release.Targets["darwin/pkg"]
	}
	return common.BinaryTarget(release)
}

func ApplyTarget(raw []byte, version string) error {
	app, ok := currentAppBundle()
	if !ok {
		return common.ApplyBinary(raw)
	}
	return applyAppPackage(raw, app, version)
}

func currentAppBundle() (string, bool) {
	exe, err := common.CurrentExecutable()
	if err != nil {
		return "", false
	}
	return appForExecutable(exe)
}

func containingApp(exe string) (string, bool) {
	macOS := filepath.Dir(exe)
	contents := filepath.Dir(macOS)
	app := filepath.Dir(contents)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || filepath.Ext(app) != ".app" {
		return "", false
	}
	return app, true
}

func appForExecutable(exe string) (string, bool) {
	app, ok := containingApp(exe)
	if !ok || filepath.Base(app) != appName || filepath.Base(exe) != executableName {
		return "", false
	}
	id, _ := plistValue(filepath.Join(app, "Contents", "Info.plist"), "CFBundleIdentifier")
	return app, id == bundleIdentifier
}

func plistValue(plist, key string) (string, error) {
	out, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// applyAppPackage swaps the bundle in whole: the staged one is validated before anything moves.
func applyAppPackage(raw []byte, app, version string) error {
	parent := filepath.Dir(app)
	stage, err := os.MkdirTemp(parent, ".quesma-shipper-update-")
	if err != nil {
		return fmt.Errorf("staging in %s: %w", parent, err)
	}
	defer os.RemoveAll(stage)
	stagedApp, err := expandAppPackage(raw, stage, version)
	if err != nil {
		return err
	}
	if err := unix.RenamexNp(app, stagedApp, unix.RENAME_SWAP); err != nil {
		return fmt.Errorf("replacing %s: %w", app, err)
	}
	return nil
}

// expandAppPackage unpacks the product archive under stage and validates the bundle inside it.
func expandAppPackage(raw []byte, stage, version string) (string, error) {
	pkg := filepath.Join(stage, "quesma-shipper.pkg")
	if err := platform.WriteAtomic(pkg, raw, 0o600); err != nil {
		return "", fmt.Errorf("writing staged package: %w", err)
	}
	expanded := filepath.Join(stage, "expanded")
	if out, err := exec.Command("/usr/sbin/pkgutil", "--expand-full", pkg, expanded).CombinedOutput(); err != nil {
		return "", fmt.Errorf("extracting package: %w: %s", err, strings.TrimSpace(string(out)))
	}
	stagedApp := filepath.Join(expanded, componentPackage, "Payload", "Applications", appName)
	if err := validateAppBundle(stagedApp, version); err != nil {
		return "", err
	}
	return stagedApp, nil
}

func validateAppBundle(app, version string) error {
	info, err := os.Lstat(app)
	if err != nil {
		return fmt.Errorf("update does not contain %s: %w", appName, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("update %s is not a directory", appName)
	}
	plist := filepath.Join(app, "Contents", "Info.plist")
	for key, want := range map[string]string{"CFBundleIdentifier": bundleIdentifier, releaseVersionField: version} {
		got, err := plistValue(plist, key)
		if err != nil {
			return fmt.Errorf("reading %s from update: %w", key, err)
		}
		if got != want {
			return fmt.Errorf("update %s is %q, want %q", key, got, want)
		}
	}
	executable := filepath.Join(app, "Contents", "MacOS", executableName)
	if info, err := os.Stat(executable); err != nil || info.Mode()&0o111 == 0 {
		return fmt.Errorf("update has no executable Contents/MacOS/%s", executableName)
	}
	return nil
}
