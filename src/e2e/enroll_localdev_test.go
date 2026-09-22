// First contact: `local-dev`, `login` and a dev build's `update` on a machine that has nothing, so
// these start from a bare world rather than the seeded identity the rest of the tier uses.
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

func statePath(w *world) string {
	return filepath.Join(w.State, "trajectory-shipper")
}

func userConfigPath(w *world) string {
	return filepath.Join(w.Config, "trajectory-shipper", "config.yaml")
}

// A virgin machine points status and run at login; local-dev then mints an identity, writes no config,
// and a re-run keeps both the identity and the user's own config.
func TestLocalDevMintsIdentityAndWritesNoConfig(t *testing.T) {
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
	assert.Equal(t, first.InstallID, second.InstallID, "re-run changed install_id")
	cfgAfter, err := os.ReadFile(userConfigPath(w))
	require.NoError(t, err)
	assert.Equalf(t, string(own), string(cfgAfter), "re-run rewrote the user's own config file")
}

// Each refusal names what to fix, and none mints an identity on the way out.
func TestRefusalsNameTheFixAndMintNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enrolled bool
		args     []string
		want     []string
	}{
		{"login with nothing", false, []string{"login"}, []string{"login <token>"}},
		{"login without a server", false, []string{"login", "tsg1.payload.sig"}, []string{"--server"}},
		{"local-dev on a logged-in install", true, []string{"local-dev"}, []string{"already logged in", "acme"}},
		// Every release orders above a dev version, so a dev build must refuse and name the override.
		{"update on a dev build", false, []string{"update"}, []string{"dev build", "make build"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := stageBareWorld(t)
			if tc.enrolled {
				rec := backend.Enrollment{InstallID: testInstallID, Organization: "acme", Endpoint: "https://cp.example"}
				require.NoError(t, os.MkdirAll(statePath(w), 0o700))
				require.NoError(t, rec.Save(statePath(w)))
			}
			out, err := runExpectingFailure(t, tc.args...)
			require.Errorf(t, err, "%v succeeded:\n%s", tc.args, out)
			for _, want := range tc.want {
				assert.Containsf(t, err.Error(), want, "refusal does not mention %q", want)
			}
			assert.NoFileExists(t, filepath.Join(statePath(w), identity.FileName), "the refusal minted an identity")
		})
	}
}

func TestLocalDevSurfacesUnreadableIdentity(t *testing.T) {
	w := stageBareWorld(t)
	if err := os.MkdirAll(statePath(w), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath(w), identity.FileName), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runExpectingFailure(t, "local-dev")
	if err == nil {
		t.Fatalf("local-dev over a corrupt identity succeeded:\n%s", out)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error does not surface the read failure: %v", err)
	}
	if strings.Contains(err.Error(), "refusing to mint") {
		t.Errorf("error is Mint's overwrite refusal, not the unit's own failure: %v", err)
	}
}

func TestLocalDevPreviewsButRunStillWaitsForEnrollment(t *testing.T) {
	w := stageBareWorld(t)
	run(t, "local-dev")
	stageClaude(t, w, realUsername(t))

	out := run(t, "preview")
	if !strings.Contains(out, claudeSource) {
		t.Fatalf("preview on a standalone install decided nothing:\n%s", out)
	}

	assertWaitsForEnrollment(t)
}

func assertWaitsForEnrollment(t *testing.T) {
	t.Helper()
	out, err := runUntilCancelled(t, "run", "--once")
	if err != nil {
		t.Fatalf("cancelled wait failed: %v", err)
	}
	if !strings.Contains(out, "waiting for enrollment") || !strings.Contains(out, "quesma-shipper login") {
		t.Errorf("the enrollment wait was not logged:\n%s", out)
	}
}
