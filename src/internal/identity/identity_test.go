package identity_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
)

func TestMintThenLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	minted, err := identity.Mint(dir)
	require.NoErrorf(t, err, "mint: %v", err)
	loaded, err := identity.Load(dir)
	require.NoErrorf(t, err, "load: %v", err)

	assert.Truef(t, loaded.InstallID == minted.InstallID, "install_id: got %s want %s", loaded.InstallID, minted.InstallID)
	assert.Equal(t, minted.Identity.String(), loaded.Identity.String(), "age identity did not survive the round trip")
	assert.Equal(t, string(minted.NameKey), string(loaded.NameKey), "name_key did not survive the round trip")
	if !loaded.CreatedAt.Equal(minted.CreatedAt) {
		t.Errorf("created_at: got %s want %s", loaded.CreatedAt, minted.CreatedAt)
	}
}

// The whole unit is one file so that on an ephemeral host it goes on the durable volume or none
// of it does: a fresh name_key re-ships every file, a fresh age identity strands every archive.
func TestUnitIsOneFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	if len(entries) != 1 || entries[0].Name() != identity.FileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected exactly %s, got %v", identity.FileName, names)
	}
}

func TestMintIsSecretByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, identity.FileName))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
}

// Minting over an existing unit would orphan every object the previous one named and every
// archive it could decrypt, so it has to be refused.
func TestMintRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Mint(dir); err == nil {
		t.Fatal("a second mint into the same dir must be refused")
	}
}

// A unit readable by group or world is a finding, not something to repair silently.
func TestLoadRefusesLooseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, identity.FileName)
	require.NoError(t, os.Chmod(path, 0o644))
	_, err := identity.Load(dir)
	require.Error(t, err, "a group/world-readable unit must be refused")
	assert.Containsf(t, err.Error(), "world-accessible", "error should name the permission problem, got: %v", err)
}

func TestLoadRejectsForeignSchema(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, identity.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	bumped := strings.Replace(string(raw), `"identity_schema": 1`, `"identity_schema": 2`, 1)
	require.NotEqual(t, string(raw), bumped, "test could not bump identity_schema; file shape changed")
	require.NoError(t, os.WriteFile(path, []byte(bumped), 0o600))
	if _, err := identity.Load(dir); err == nil {
		t.Fatal("an unknown identity_schema must be rejected, never guessed at")
	}
}

// A recipient that no longer matches its identity means the naming and encryption halves may no
// longer belong together.
func TestLoadRejectsMismatchedRecipient(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Mint(dir); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	stranger, err := identity.Mint(other)
	require.NoError(t, err)

	path := filepath.Join(dir, identity.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	mine, err := identity.Load(dir)
	require.NoError(t, err)
	swapped := strings.Replace(string(raw),
		mine.Recipient().String(), stranger.Recipient().String(), 1)
	require.NotEqual(t, string(raw), swapped, "test could not swap the recipient; file shape changed")
	require.NoError(t, os.WriteFile(path, []byte(swapped), 0o600))
	if _, err := identity.Load(dir); err == nil {
		t.Fatal("a recipient that disagrees with the identity must be rejected")
	}
}

// The private age identity and the name_key must not reach a log line by accident, which is the
// likeliest way either escapes.
func TestUnitRedactsWhenFormatted(t *testing.T) {
	dir := t.TempDir()
	u, err := identity.Mint(dir)
	require.NoError(t, err)

	secret := u.Identity.String()
	for _, rendered := range []string{
		fmt.Sprintf("%v", *u),
		fmt.Sprintf("%s", *u),
		fmt.Sprintf("%+v", *u),
		fmt.Sprintf("%#v", *u),
		(*u).String(),
	} {
		assert.NotContainsf(t, rendered, secret, "formatted unit leaked the private age identity: %s", rendered)
		assert.NotContainsf(t, rendered, hexOf(u.NameKey), "formatted unit leaked the name_key: %s", rendered)
		assert.Containsf(t, rendered, "REDACTED", "formatted unit should say REDACTED, got: %s", rendered)
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&0x0f])
	}
	return string(out)
}

// Two installs must not collide on either the naming secret or the identity.
func TestMintIsUniquePerInstall(t *testing.T) {
	a, err := identity.Mint(t.TempDir())
	require.NoError(t, err)
	b, err := identity.Mint(t.TempDir())
	require.NoError(t, err)
	assert.True(t, a.InstallID != b.InstallID, "two installs share an install_id")
	assert.NotEqual(t, string(b.NameKey), string(a.NameKey), "two installs share a name_key")
	assert.NotEqual(t, b.Identity.String(), a.Identity.String(), "two installs share an age identity")
}
