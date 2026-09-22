package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

// An installed update and its pending restart must remain distinguishable in every warning.
func TestUpdateRestartWarnings(t *testing.T) {
	timeout := serviceStateTimeoutError(context.DeadlineExceeded)
	require.ErrorIs(t, timeout, context.DeadlineExceeded)
	for _, tc := range []struct {
		name, message string
		want          []string
	}{
		{"service state timeout", timeout.Error(),
			[]string{"5s", "update is installed", "restart was not requested"}},
		{"restart timeout", restartTimeoutWarning(5*time.Minute + 30*time.Second),
			[]string{"5m30s", "update is installed", "new version"}},
		{"unreadable config", configUnreadableWarning(errors.New("state_dir is not absolute")),
			[]string{"state_dir is not absolute", "not restarted", "previous version"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				assert.Contains(t, tc.message, want)
			}
			if cmd := packaging.RestartCommand(); cmd != "" {
				assert.Contains(t, tc.message, cmd)
			}
		})
	}
}

// Loaded is a detection result, and detection is what goes wrong. Gating the restart on it meant
// `update` printed the new version, exited 0, and left the daemon running the old binary.
func TestRestartWantedIgnoresWhetherTheServiceReportsItselfLoaded(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   packaging.ServiceStatus
		want bool
	}{
		{"a loaded service is restarted", packaging.ServiceStatus{Installed: true, Loaded: true}, true},
		// The Windows regression: the task was running, its definition could not be read, and
		// Loaded came back false. Also the macOS "present but NOT loaded" plist.
		{"an installed service that does not report itself loaded is still restarted",
			packaging.ServiceStatus{Installed: true, Loaded: false}, true},
		{"no service entry is the one case with nothing to restart", packaging.ServiceStatus{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, restartWanted(tc.st), tc.want)
		})
	}
}

// Every branch of the boot-time gate is a promise: dev builds never self-update,
// SHIPPER_NO_SELFUPDATE always wins, and the re-exec guard allows exactly one hop per boot.
func TestTheBootGateKeepsItsPromises(t *testing.T) {
	release := app.Build{Version: "0.0.1-123.abcdef123456", Release: true}
	dev := app.Build{Version: "0.0.0-031a7faa8c16"}

	env := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}

	for _, tc := range []struct {
		name    string
		build   app.Build
		vars    map[string]string
		hop     string
		wantRun bool
		loud    bool // a skip the operator should see a line about
	}{
		{"a released daemon updates", release, nil, "", true, false},
		{"a dev build never does, silently", dev, nil, "", false, false},
		{"a dev build ignores even a stray re-exec guard", dev,
			map[string]string{app.ReexecGuardEnv: "0.0.1-9.x"}, "", false, false},
		{"the env kill switch wins and says so", release, map[string]string{app.NoSelfUpdateEnv: "1"}, "", false, true},
		{"the hop guard stops a second update this boot and says so", release,
			map[string]string{app.ReexecGuardEnv: "0.0.1-124.def456def456"}, "", false, true},
		{"a hop to a version we are not running blocks and says so", release, nil,
			"0.0.1-124.def456def456", false, true},
		{"a hop that landed on this build stops blocking", release, nil, release.Version, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, why := selfUpdateGate(tc.build, env(tc.vars), tc.hop)
			assert.Equalf(t, tc.wantRun, run, "run = %v, want %v", run, tc.wantRun)
			assert.Equalf(t, tc.loud, (why != ""), "why = %q, want loud=%v", why, tc.loud)
		})
	}
}
