package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

func TestRecycleRetriesAFailedSupervisionProbe(t *testing.T) {
	started := time.Unix(0, 0)
	probes := 0
	serviceLoaded := func() bool {
		probes++
		return probes > 1
	}
	require.False(t, recycleDue(started, started.Add(recycleAfter-time.Second), serviceLoaded), "due before the uptime threshold")
	require.Equal(t, 0, probes, "supervision was probed before recycling was due")
	require.False(t, recycleDue(started, started.Add(recycleAfter), serviceLoaded), "a failed supervision probe allowed recycling")
	require.True(t, recycleDue(started, started.Add(recycleAfter+time.Second), serviceLoaded), "a transient failure disabled recycling for good")
	require.Equal(t, 2, probes)
}

// Catch-up is only for successful truncated work; failures keep the normal interval.
func TestNextDelay(t *testing.T) {
	sinkDown := errors.New("sink unreachable")
	for _, tc := range []struct {
		report formats.Report
		err    error
		want   time.Duration
	}{
		{formats.Report{Truncated: true, Shipped: 64}, nil, app.CatchUpDelay},
		{formats.Report{}, nil, config.DefaultTick},
		{formats.Report{Truncated: true}, sinkDown, config.DefaultTick},
		{formats.Report{Truncated: true, Shipped: 64}, sinkDown, config.DefaultTick},
		{formats.Report{Truncated: true, Failed: 64}, nil, config.DefaultTick},
	} {
		assert.Equal(t, tc.want, app.NextDelay(tc.report, tc.err, config.DefaultTick), "%+v %v", tc.report, tc.err)
	}
}

// The daemon must survive a panic in a tick; a clean tick passes through untouched.
func TestRecoverFlush(t *testing.T) {
	var errOut strings.Builder
	rep, err, panicked := recoverFlush(&errOut, nil, func() (formats.Report, error) {
		var boom *formats.Report
		return *boom, nil // nil dereference, the kind of bug this exists for
	})
	require.True(t, panicked)
	assert.Error(t, err)
	assert.Equal(t, 0, rep.Shipped)
	assert.Contains(t, errOut.String(), "PANIC in flush")
	// The stack is the whole value of recovering: without it there is no way to find the cause.
	assert.Contains(t, errOut.String(), "run_test.go", "no stack in the output")

	errOut.Reset()
	rep, err, panicked = recoverFlush(&errOut, nil, func() (formats.Report, error) { return formats.Report{Shipped: 3}, nil })
	require.True(t, !panicked && err == nil, "clean tick: panicked=%v err=%v", panicked, err)
	assert.Equal(t, 3, rep.Shipped)
	assert.Empty(t, errOut.String())
}

func TestServiceInstallationBelongsToThePackager(t *testing.T) {
	for _, cmd := range serviceCmd().Commands() {
		require.NotEqual(t, "install", cmd.Name(), "service install is exposed through the CLI")
	}
}

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

// Dev builds never self-update, the env switch wins, and one hop per boot; loud skips say why.
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
