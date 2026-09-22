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
	for message, wants := range map[string][]string{
		timeout.Error(): {"5s", "update is installed", "restart was not requested"},
		restartTimeoutWarning(5*time.Minute + 30*time.Second):            {"5m30s", "update is installed", "new version"},
		configUnreadableWarning(errors.New("state_dir is not absolute")): {"state_dir is not absolute", "not restarted", "previous version"},
	} {
		if cmd := packaging.RestartCommand(); cmd != "" {
			wants = append(wants, cmd)
		}
		for _, want := range wants {
			assert.Contains(t, message, want)
		}
	}
}

// Dev builds never self-update, SHIPPER_NO_SELFUPDATE always wins, and the re-exec guard allows
// exactly one hop per boot; every skip the operator should know about says why.
func TestTheBootGateKeepsItsPromises(t *testing.T) {
	release := app.Build{Version: "0.0.1-123.abcdef123456", Release: true}
	dev := app.Build{Version: "0.0.0-031a7faa8c16"}
	for _, tc := range []struct {
		name          string
		build         app.Build
		vars          map[string]string
		hop           string
		wantRun, loud bool
	}{
		{"a released daemon updates", release, nil, "", true, false},
		{"a dev build never does, silently", dev, nil, "", false, false},
		{"a dev build ignores even a stray re-exec guard", dev, map[string]string{app.ReexecGuardEnv: "0.0.1-9.x"}, "", false, false},
		{"the env kill switch wins", release, map[string]string{app.NoSelfUpdateEnv: "1"}, "", false, true},
		{"the hop guard stops a second update this boot", release, map[string]string{app.ReexecGuardEnv: "0.0.1-124.def456def456"}, "", false, true},
		{"a hop to a version we are not running blocks", release, nil, "0.0.1-124.def456def456", false, true},
		{"a hop that landed on this build stops blocking", release, nil, release.Version, true, false},
	} {
		run, why := selfUpdateGate(tc.build, func(k string) string { return tc.vars[k] }, tc.hop)
		assert.Equal(t, tc.wantRun, run, tc.name)
		assert.Equal(t, tc.loud, why != "", "%s: why = %q", tc.name, why)
	}
}
