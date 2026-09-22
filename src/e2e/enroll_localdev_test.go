// First contact on a machine that has nothing: `local-dev`, `login`, and `update` on a dev build, which
// must refuse because every release orders above a dev version. These start from a bare world.
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	backend "github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
)

// A virgin machine points status and run at login; local-dev then mints an identity, writes no config,
// and a re-run keeps both the identity and the user's own config.
func TestLocalDevMintsIdentityAndKeepsItOnRerun(t *testing.T) {
	w := stageBareWorld(t)
	before, err := runExpectingFailure(t, "status")
	assert.Truef(t, err != nil && strings.Contains(before, "not logged in") && strings.Contains(before, "quesma-shipper login"), "status on a virgin machine does not point at login (err %v):\n%s", err, before)
	assertWaitsForEnrollment(t)
	require.NoFileExists(t, filepath.Join(statePath(w), identity.FileName), "waiting for enrollment minted an identity")

	out := run(t, "local-dev")

	first, err := identity.Load(statePath(w))
	require.NoErrorf(t, err, "no loadable identity after local-dev: %v", err)
	assert.Containsf(t, out, first.InstallID.String(), "output does not name the identity:\n%s", out)
	assert.NoFileExistsf(t, userConfigPath(w), "local-dev must not write a config file")
	assert.NoFileExistsf(t, filepath.Join(statePath(w), backend.EnrollmentFile), "local-dev must not write an enrollment record")
	after := run(t, "status")
	assert.Truef(t, strings.Contains(after, "shipper local") && strings.Contains(after, "nothing is sent"), "status after local-dev does not describe the local install and its destination:\n%s", after)

	own := []byte("config_version: 1\n# mine\n")
	require.NoError(t, os.MkdirAll(filepath.Dir(userConfigPath(w)), 0o700))
	require.NoError(t, os.WriteFile(userConfigPath(w), own, 0o600))
	run(t, "local-dev")

	second, err := identity.Load(statePath(w))
	require.NoError(t, err)
	assert.Truef(t, first.InstallID == second.InstallID, "re-run changed install_id: %s -> %s", first.InstallID, second.InstallID)
	cfgAfter, err := os.ReadFile(userConfigPath(w))
	require.NoError(t, err)
	assert.Equalf(t, string(own), string(cfgAfter), "re-run rewrote the user's own config file")
}

func TestLoginWithoutTokenOrServerFails(t *testing.T) {
	w := stageBareWorld(t)

	out, err := runExpectingFailure(t, "login")
	require.Errorf(t, err, "login with nothing succeeded:\n%s", out)
	assert.Containsf(t, err.Error(), "login <token>", "error does not show how to pass the token: %v", err)

	out, err = runExpectingFailure(t, "login", "tsg1.payload.sig")
	require.Errorf(t, err, "login with a token and no server succeeded:\n%s", out)
	assert.Containsf(t, err.Error(), "--server", "error does not name the missing server: %v", err)
	assert.NoFileExistsf(t, filepath.Join(statePath(w), identity.FileName), "a refused login minted an identity anyway")
}

func TestLocalDevRefusesLoggedInInstall(t *testing.T) {
	w := stageBareWorld(t)

	rec := backend.Enrollment{InstallID: testInstallID, Organization: "acme", Endpoint: "https://cp.example"}
	require.NoError(t, os.MkdirAll(statePath(w), 0o700))
	require.NoError(t, rec.Save(statePath(w)))

	out, err := runExpectingFailure(t, "local-dev")
	require.Errorf(t, err, "local-dev on a logged-in install succeeded:\n%s", out)
	for _, want := range []string{"already logged in", "acme"} {
		assert.Containsf(t, err.Error(), want, "refusal does not mention %q: %v", want, err)
	}
	assert.NoFileExistsf(t, filepath.Join(statePath(w), identity.FileName), "the refused local-dev minted an identity")
}

func TestLocalDevSurfacesUnreadableIdentity(t *testing.T) {
	w := stageBareWorld(t)
	require.NoError(t, os.MkdirAll(statePath(w), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(statePath(w), identity.FileName), []byte("not json"), 0o600))

	out, err := runExpectingFailure(t, "local-dev")
	require.Errorf(t, err, "local-dev over a corrupt identity succeeded:\n%s", out)
	assert.Containsf(t, err.Error(), "parse", "error does not surface the read failure: %v", err)
	assert.NotContainsf(t, err.Error(), "refusing to mint", "error is Mint's overwrite refusal, not the unit's own failure: %v", err)
}

func TestLocalDevPreviewsButRunStillWaitsForEnrollment(t *testing.T) {
	w := stageBareWorld(t)
	run(t, "local-dev")
	stageClaude(t, w, realUsername(t))

	out := run(t, "preview")
	require.Containsf(t, out, claudeSource, "preview on a standalone install decided nothing:\n%s", out)

	assertWaitsForEnrollment(t)
}

func assertWaitsForEnrollment(t *testing.T) {
	t.Helper()
	out, err := runUntilCancelled(t, "run", "--once")
	require.NoErrorf(t, err, "cancelled wait failed: %v", err)
	assert.Truef(t, strings.Contains(out, "waiting for enrollment") && strings.Contains(out, "quesma-shipper login"), "the enrollment wait was not logged:\n%s", out)
}

func TestUpdateOnADevBuildRefusesAndNamesTheOverride(t *testing.T) {
	stageBareWorld(t)

	out, err := runExpectingFailure(t, "update")
	require.Errorf(t, err, "update on a dev build succeeded:\n%s", out)
	for _, want := range []string{"dev build", "make build"} {
		assert.Containsf(t, err.Error(), want, "the refusal does not mention %q: %v", want, err)
	}
}
