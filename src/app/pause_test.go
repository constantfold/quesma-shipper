package app_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Pausing must not depend on configuration parsing: a user must be able to resume even when
// the configuration needs repair.
func TestPauseWorksUnderABrokenConfig(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	stateHome := filepath.Join(home, ".state")
	stateDir := filepath.Join(stateHome, "trajectory-shipper")

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)

	// A config file that does not parse.
	require.NoError(t, os.MkdirAll(filepath.Join(configHome, "trajectory-shipper"), 0o700))
	broken := filepath.Join(configHome, "trajectory-shipper", "config.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("config_version: 1\n bad: indent: here\n"), 0o600))
	if _, _, err := app.ResolveEffective(); err == nil {
		t.Fatal("the fixture config parses; this test proves nothing")
	}

	warning, err := app.Pause(time.Now().Add(time.Hour))
	require.NoErrorf(t, err, "pause failed under broken configuration: %v", err)
	assert.Containsf(t, warning, "does not resolve", "the fallback was silent: %q", warning)
	require.True(t, platform.Read(stateDir).Paused, "pausing under broken configuration did not take effect")

	wasPaused, warning, err := app.Resume()
	require.NoErrorf(t, err, "resume failed under broken configuration: %v", err)
	require.True(t, wasPaused, "resume did not report the existing pause")
	assert.Containsf(t, warning, "does not resolve", "the fallback was silent: %q", warning)
	require.True(t, !platform.Read(stateDir).Paused, "resuming under broken configuration did not take effect")
}

// With valid configuration, pause and resume use its state directory rather than the default.
func TestPauseHonoursAResolvedStateDir(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	moved := filepath.Join(home, "elsewhere")

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".state"))

	require.NoError(t, os.MkdirAll(filepath.Join(configHome, "trajectory-shipper"), 0o700))
	body := "config_version: 1\nstate_dir: " + moved + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "trajectory-shipper", "config.yaml"),
		[]byte(body), 0o600))

	warning, err := app.Pause(time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equalf(t, "", warning, "warned on a configuration that resolves cleanly: %q", warning)
	require.True(t, platform.Read(moved).Paused, "pause was not written to the configured state directory")

	wasPaused, warning, err := app.Resume()
	require.NoError(t, err)
	require.True(t, wasPaused, "resume did not report the existing pause")
	assert.Equalf(t, "", warning, "warned on a configuration that resolves cleanly: %q", warning)
	require.True(t, !platform.Read(moved).Paused, "resume did not clear the configured pause state")
}

// The identity unit and the fingerprint document live in ONE state directory: they persist
// together or not at all, which is what makes a rebuilt ephemeral host the SAME install.
func TestOneResolvedStateDirectoryForEveryArtifact(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	moved := filepath.Join(home, "moved-state")

	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".state"))

	require.NoError(t, os.MkdirAll(filepath.Join(configHome, "trajectory-shipper"), 0o700))
	body := "config_version: 1\nstate_dir: " + moved + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(configHome, "trajectory-shipper", "config.yaml"),
		[]byte(body), 0o600))

	eff, paths, err := app.ResolveEffective()
	require.NoError(t, err)
	// The two values have to agree: half the CLI reads one and the engine reads the other.
	assert.Equalf(t, moved, paths.StateDir, "paths.StateDir = %q, want %q", paths.StateDir, moved)
	assert.Equalf(t, moved, eff.StateDir, "eff.StateDir = %q, want %q", eff.StateDir, moved)
	assert.Equalf(t, eff.StateDir, paths.StateDir, "the CLI and the engine would use different state directories: %q vs %q", paths.StateDir, eff.StateDir)
}
