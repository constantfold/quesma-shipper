package identity_test

import (
	"encoding/hex"
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

// The identity persists as one private file; neither a second mint nor incidental formatting may expose or replace its secrets.
func TestIdentityLifecycle(t *testing.T) {
	dir := t.TempDir()
	minted, err := identity.Mint(dir)
	require.NoError(t, err)
	loaded, err := identity.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, minted.InstallID, loaded.InstallID)
	assert.Equal(t, minted.Identity.String(), loaded.Identity.String())
	assert.Equal(t, minted.NameKey, loaded.NameKey)
	assert.True(t, minted.CreatedAt.Equal(loaded.CreatedAt))

	t.Run("private file permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no POSIX modes")
		}
		path := filepath.Join(dir, identity.FileName)
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
		require.NoError(t, os.Chmod(path, 0o644))
		_, err = identity.Load(dir)
		require.ErrorContains(t, err, "world-accessible", "a loose mode must be reported, never silently repaired")
		require.NoError(t, os.Chmod(path, 0o600))
	})

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, identity.FileName, entries[0].Name())
	_, err = identity.Mint(dir)
	require.Error(t, err, "minting over an existing unit must be refused")

	other, err := identity.Mint(t.TempDir())
	require.NoError(t, err)
	assert.NotEqual(t, minted.InstallID, other.InstallID)
	assert.NotEqual(t, minted.NameKey, other.NameKey)
	assert.NotEqual(t, minted.Identity.String(), other.Identity.String())

	for _, rendered := range []string{
		fmt.Sprintf("%v", *minted), fmt.Sprintf("%s", *minted),
		fmt.Sprintf("%+v", *minted), fmt.Sprintf("%#v", *minted), minted.String(),
	} {
		assert.NotContains(t, rendered, minted.Identity.String(), "formatted unit leaked its private age identity")
		assert.NotContains(t, rendered, hex.EncodeToString(minted.NameKey), "formatted unit leaked its name key")
		assert.Contains(t, rendered, "REDACTED")
	}
}

// Schema and recipient mismatches must fail for their own reason, never yield a guessed identity.
func TestLoadRejectsChangedIdentityFields(t *testing.T) {
	dir := t.TempDir()
	mine, err := identity.Mint(dir)
	require.NoError(t, err)
	stranger, err := identity.Mint(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(dir, identity.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, tc := range []struct{ name, from, to, reason string }{
		{"foreign schema", `"identity_schema": 1`, `"identity_schema": 2`, "refusing to guess"},
		{"mismatched recipient", mine.Recipient().String(), stranger.Recipient().String(), "age_recipient does not match age_identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(string(raw), tc.from, tc.to, 1)
			require.NotEqual(t, string(raw), changed, "fixture field was not replaced")
			require.NoError(t, os.WriteFile(path, []byte(changed), 0o600))
			_, err := identity.Load(dir)
			require.ErrorContains(t, err, tc.reason)
		})
	}
}
