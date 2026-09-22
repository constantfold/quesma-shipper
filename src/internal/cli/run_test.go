package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/app"
	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
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
