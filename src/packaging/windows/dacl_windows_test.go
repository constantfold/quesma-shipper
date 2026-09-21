//go:build windows

package windows

import (
	"os/exec"
	"os/user"
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
	if err := verifyInstallDir(t.TempDir(), currentSID(t)); err != nil {
		t.Fatalf("verifyInstallDir() = %v, want nil", err)
	}
}

func TestVerifyInstallDirRejectsADirectoryAnotherAccountCanChange(t *testing.T) {
	dir := t.TempDir()
	// BUILTIN\Users by SID, so the grant does not depend on the system's display language.
	out, err := exec.Command("icacls.exe", dir, "/grant", "*"+sidUsers+":(M)").CombinedOutput()
	if err != nil {
		t.Skipf("cannot grant Users write access to %s: %v: %s", dir, err, out)
	}

	err = verifyInstallDir(dir, currentSID(t))
	require.False(t, err == nil, "verifyInstallDir() = nil, want an error naming the trustee")
	require.Falsef(t, !strings.Contains(err.Error(), "Users"), "verifyInstallDir() = %v, want the message to name BUILTIN\\Users", err)
}

// The installing user's own FullControl must not read as a finding against their own directory.
func TestDirectoryACEsReadsTheInstallersOwnEntry(t *testing.T) {
	dir := t.TempDir()
	aces, err := directoryACEs(dir)
	require.NoError(t, err)
	require.False(t, len(aces) == 0, "directoryACEs() returned no entries for a directory that has a DACL")
	sid := currentSID(t)
	for _, a := range aces {
		if strings.EqualFold(a.SID, sid) && a.Allow && a.Mask&writeMask != 0 {
			return
		}
	}
	t.Fatalf("no allow-write entry for the installing user %s in %+v", sid, aces)
}
