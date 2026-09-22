//go:build darwin

package macos

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

func TestHomebrewUpdateReexec(t *testing.T) {
	if os.Getenv("QUESMA_TEST_BREW_REEXEC") == "1" {
		release := common.Release{Targets: map[string]string{"darwin/" + runtime.GOARCH: "raw-binary", "darwin/pkg": "package"}}
		require.Equal(t, "raw-binary", UpdateTarget(release))
		raw, err := os.ReadFile(os.Getenv("QUESMA_TEST_BREW_REPLACEMENT"))
		require.NoError(t, err)
		require.NoError(t, ApplyTarget(raw, "1.0.1"))
		os.Args = []string{os.Args[0], "self-update restarted"}
		t.Fatal(common.ReExec())
	}
	root := t.TempDir()
	helper := filepath.Join(root, "replacement.go")
	require.NoError(t, os.WriteFile(helper, []byte("package main\nimport (\"fmt\"; \"os\")\nfunc main() { fmt.Println(os.Args[1]) }\n"), 0o600))
	replacement := filepath.Join(root, "replacement")
	out, err := exec.Command("go", "build", "-o", replacement, helper).CombinedOutput()
	require.NoErrorf(t, err, "build replacement: %s", out)
	executable, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(executable)
	require.NoError(t, err)
	installed := filepath.Join(root, "Caskroom", "quesma-shipper", "1.0.0", "quesma-shipper")
	require.NoError(t, os.MkdirAll(filepath.Dir(installed), 0o755))
	require.NoError(t, os.WriteFile(installed, raw, 0o755))
	link := filepath.Join(root, "shipper")
	require.NoError(t, os.Symlink(installed, link))
	plist := writePlist(t, root, installed)
	cmd := exec.Command(link, "-test.run=^TestHomebrewUpdateReexec$")
	cmd.Env = append(os.Environ(), "QUESMA_TEST_BREW_REEXEC=1", "QUESMA_TEST_BREW_REPLACEMENT="+replacement)
	out, err = cmd.CombinedOutput()
	require.NoErrorf(t, err, "update and reexec: %s", out)
	require.Equal(t, "self-update restarted\n", string(out))
	target, err := os.Readlink(link)
	require.NoError(t, err)
	require.Equal(t, installed, target, "command link changed")
	require.Equal(t, common.ServiceProgram(Status{Path: plist}), installed)
	updated, err := os.ReadFile(installed)
	require.Truef(t, err == nil && !bytes.Equal(raw, updated), "binary was not replaced: %v", err)
	out, err = exec.Command(link, "next launch").CombinedOutput()
	require.NoErrorf(t, err, "launch after update: %s", out)
	require.Equal(t, "next launch\n", string(out))
}

func TestHomebrewServiceOwnership(t *testing.T) {
	brew := "/opt/brew & tools/Caskroom/quesma-shipper/1.0.0/quesma-shipper"
	upgrade := "/opt/brew & tools/Caskroom/quesma-shipper/1.0.1/quesma-shipper"
	native := "/Users/me/Applications/Quesma Shipper.app/Contents/MacOS/quesma-shipper"
	for _, tc := range []struct {
		name, previous, next string
		allowed              bool
	}{
		{"fresh install", "", brew, true},
		{"brew reinstall", brew, brew, true},
		{"brew upgrade", brew, upgrade, true},
		{"native reinstall", native, native, true},
		{"native to brew needs removal", native, brew, false},
		{"brew to native needs removal", brew, native, false},
		{"another brew prefix", brew, "/usr/local/Caskroom/quesma-shipper/1.0.1/quesma-shipper", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plist := filepath.Join(t.TempDir(), "agent.plist")
			if tc.previous != "" {
				plist = writePlist(t, t.TempDir(), tc.previous)
				require.Equal(t, common.ServiceProgram(Status{Path: plist}), tc.previous)
			}
			require.Equal(t, (checkInstallOwner(tc.next, plist) == nil), tc.allowed)
		})
	}
}

func TestHomebrewProgramCannotRemoveItself(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "Caskroom", "quesma-shipper", "1.0.0", "quesma-shipper")
	require.NoError(t, os.MkdirAll(filepath.Dir(exe), 0o755))
	require.NoError(t, os.WriteFile(exe, []byte("installed binary"), 0o755))
	_, err := RemoveProgram(exe)
	require.ErrorContains(t, err, "brew uninstall")
	require.FileExists(t, exe)
}

func TestHomebrewUninstallOwnership(t *testing.T) {
	exe := "/opt/homebrew/Caskroom/quesma-shipper/1.0.0/quesma-shipper"
	for _, tc := range []struct {
		name, program string
		owned, bad    bool
	}{
		{"current cask", exe, true, false},
		{"replacement cask", "/opt/homebrew/Caskroom/quesma-shipper/1.0.1/quesma-shipper", false, false},
		{"native installation", "/Users/me/Applications/Quesma Shipper.app/Contents/MacOS/quesma-shipper", false, false},
		{"missing entry", "", false, false},
		{"invalid entry", "invalid", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plist := filepath.Join(t.TempDir(), "agent.plist")
			if tc.program != "" {
				plist = writePlist(t, t.TempDir(), tc.program)
			}
			if tc.bad {
				require.NoError(t, os.WriteFile(plist, []byte("broken plist"), 0o600))
			}
			owned, err := ownsHomebrewService(exe, plist)
			require.Truef(t, owned == tc.owned && err != nil == tc.bad, "ownership = %v, %v", owned, err)
		})
	}
}

// writePlist installs a LaunchAgent entry for program under dir and returns its path.
func writePlist(t *testing.T, dir, program string) string {
	t.Helper()
	spec := testSpec()
	spec.Executable = program
	plist := filepath.Join(dir, "agent.plist")
	require.NoError(t, os.WriteFile(plist, []byte(renderPlist(spec)), 0o600))
	return plist
}
