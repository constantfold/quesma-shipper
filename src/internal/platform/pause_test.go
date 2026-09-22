package platform_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

func TestPauseFlagLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, subdir, reason string
	}{
		{"round trip", "", "laptop going to a client site"},
		{"before init", "not/created/yet", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), tc.subdir)
			require.False(t, platform.Read(dir).Paused, "fresh install")
			for range 3 {
				require.NoError(t, platform.Set(dir, tc.reason, time.Now(), time.Time{}))
				// Every daemon tick must see the flag until an explicit resume.
				for range 5 {
					got := platform.Read(dir)
					require.True(t, got.Paused)
					assert.Equal(t, tc.reason, got.Reason)
					assert.NotEmpty(t, got.At)
				}
				_, err := os.Stat(filepath.Join(dir, platform.File))
				require.NoError(t, err)
			}
			for range 3 {
				require.NoError(t, platform.Clear(dir))
				require.False(t, platform.Read(dir).Paused)
			}
		})
	}
}

// The failure directions are not symmetric, so the fail-closed choice is tested explicitly.
func TestAnUnreadableFlagReadsAsPaused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"not json at all", "paused\n"},
		{"truncated mid-write", `{"paused":tr`},
		// The file's PRESENCE is the switch: honouring the field would let a partial write silently resume collection.
		{"the flag says paused false", `{"paused":false,"at":"2026-07-30T00:00:00Z"}`},
		{"empty file", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, platform.File), []byte(tc.body), 0o644))
			got := platform.Read(dir)
			require.True(t, got.Paused, "a flag file that exists but does not parse read as NOT paused: "+
				"that direction resumes collection on a machine whose owner stopped it")
			assert.True(t, tc.body == "" || got.Reason != "" || tc.name == "the flag says paused false", "no reason given, so `status` could not explain the state")
		})
	}
}

// The structural form of "no config can undo it": the guarantee is in what this package cannot see.
func TestPauseCannotSeeConfigOrBackend(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/QuesmaOrg/quesma-shipper/internal/platform").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	forbidden := []string{
		"github.com/QuesmaOrg/quesma-shipper/internal/config",
		"github.com/QuesmaOrg/quesma-shipper/internal/controlplane",
		"net/http",
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbidden {
			assert.NotEqual(t, dep, f)
		}
	}
}
