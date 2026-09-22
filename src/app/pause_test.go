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

// A broken configuration must not prevent pausing or resuming collection.
func TestPauseStateDirectory(t *testing.T) {
	for _, statePath := range []string{"broken-config", "elsewhere", "moved-state"} {
		t.Run(statePath, func(t *testing.T) {
			home := t.TempDir()
			configHome := filepath.Join(home, ".config")
			stateHome := filepath.Join(home, ".state")
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", configHome)
			t.Setenv("XDG_STATE_HOME", stateHome)

			stateDir := filepath.Join(home, statePath)
			body := "config_version: 1\nstate_dir: " + stateDir + "\n"
			wantWarning := ""
			if statePath == "broken-config" {
				stateDir = filepath.Join(stateHome, "trajectory-shipper")
				body = "config_version: 1\n bad: indent: here\n"
				wantWarning = "does not resolve"
			}
			configDir := filepath.Join(configHome, "trajectory-shipper")
			require.NoError(t, os.MkdirAll(configDir, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(body), 0o600))

			eff, paths, err := app.ResolveEffective()
			if wantWarning != "" {
				require.Error(t, err, "the fixture must fail to resolve")
			} else {
				require.NoError(t, err)
				assert.Equal(t, stateDir, paths.StateDir)
				assert.Equal(t, stateDir, eff.StateDir)
				assert.Equal(t, eff.StateDir, paths.StateDir, "CLI and engine must share state")
			}

			warning, err := app.Pause(time.Now().Add(time.Hour))
			require.NoError(t, err)
			assertPauseWarning(t, warning, wantWarning)
			require.True(t, platform.Read(stateDir).Paused)
			wasPaused, warning, err := app.Resume()
			require.NoError(t, err)
			require.True(t, wasPaused, "resume must report the existing pause")
			assertPauseWarning(t, warning, wantWarning)
			require.False(t, platform.Read(stateDir).Paused)
		})
	}
}

func assertPauseWarning(t *testing.T, warning, want string) {
	t.Helper()
	if want == "" {
		assert.Empty(t, warning)
	} else {
		assert.Contains(t, warning, want)
	}
}
