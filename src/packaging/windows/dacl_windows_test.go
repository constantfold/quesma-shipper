//go:build windows

package windows

import (
	"os/exec"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func currentSID(t *testing.T) string {
	t.Helper()
	current, err := user.Current()
	require.NoError(t, err)
	return current.Uid
}

// A directory created by this user carries the profile's own ACL: nobody else can change it.
func TestVerifyInstallDirAcceptsADirectoryOnlyThisUserCanChange(t *testing.T) {
	require.NoError(t, verifyInstallDir(t.TempDir(), currentSID(t)))
}

func TestVerifyInstallDirRejectsADirectoryAnotherAccountCanChange(t *testing.T) {
	dir := t.TempDir()
	// BUILTIN\Users by SID, so the grant does not depend on the system's display language.
	out, err := exec.Command("icacls.exe", dir, "/grant", "*"+sidUsers+":(M)").CombinedOutput()
	if err != nil {
		t.Skipf("cannot grant Users write access to %s: %v: %s", dir, err, out)
	}

	require.ErrorContains(t, verifyInstallDir(dir, currentSID(t)), "Users", "want an error naming BUILTIN\\Users")
}

// The installing user's own FullControl must not read as a finding against their own directory.
func TestDirectoryACEsReadsTheInstallersOwnEntry(t *testing.T) {
	dir := t.TempDir()
	aces, err := directoryACEs(dir)
	require.NoError(t, err)
	sid := currentSID(t)
	require.Truef(t, slices.ContainsFunc(aces, func(a ace) bool {
		return strings.EqualFold(a.SID, sid) && a.Allow && a.Mask&writeMask != 0
	}), "no allow-write entry for the installing user %s in %+v", sid, aces)
}
