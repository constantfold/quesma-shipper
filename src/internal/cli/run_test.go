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

	require.True(t, !recycleDue(started, started.Add(recycleAfter-time.Second), serviceLoaded), "recycling became due before the uptime threshold")
	require.Equalf(t, 0, probes, "supervision was probed %d times before recycling was due", probes)
	require.True(t, !recycleDue(started, started.Add(recycleAfter), serviceLoaded), "a failed supervision probe allowed recycling")
	require.True(t, recycleDue(started, started.Add(recycleAfter+time.Second), serviceLoaded), "a transient supervision failure permanently disabled recycling")
	require.Equalf(t, 2, probes, "supervision was probed %d times, want 2", probes)
}

// A truncated run left backlog on disk, so the loop comes back after the catch-up delay
// rather than the full interval.
func TestTruncatedRunEarnsTheCatchUpDelay(t *testing.T) {
	// Shipped is part of the condition: a run that collected nothing has no backlog to chase.
	require.Equal(t, app.CatchUpDelay, app.NextDelay(formats.Report{Truncated: true, Shipped: 64}, nil, config.DefaultTick))
}

func TestCompleteRunWaitsTheFullInterval(t *testing.T) {
	require.Equal(t, config.DefaultTick, app.NextDelay(formats.Report{}, nil, config.DefaultTick))
}

// An errored run keeps the full interval: re-ticking fast would make one failure a hot loop.
// A panic is the same case: recoverFlush always surfaces it as an error.
func TestErroredRunNeverEarnsTheCatchUpDelay(t *testing.T) {
	rep := formats.Report{Truncated: true}
	require.Equal(t, config.DefaultTick, app.NextDelay(rep, errors.New("sink unreachable"), config.DefaultTick))
}

// The daemon must survive a panic in a tick, so the recovery is exercised through a function
// that panics rather than through the real runtime.
func TestAPanickingTickIsRecoveredAndReported(t *testing.T) {
	var errOut strings.Builder

	rep, err, panicked := recoverFlush(&errOut, nil, func() (formats.Report, error) {
		var boom *formats.Report
		return *boom, nil // nil dereference, the kind of bug this exists for
	})

	require.True(t, panicked, "a panicking tick was not reported as panicked")
	assert.Error(t, err, "a panicking tick returned no error")
	assert.Equalf(t, 0, rep.Shipped, "a panicking tick reported %d shipped", rep.Shipped)
	out := errOut.String()
	assert.Containsf(t, out, "PANIC in flush", "the panic was not announced:\n%s", out)
	// The stack is the whole value of recovering: without it there is no way to find the cause.
	assert.Containsf(t, out, "run_test.go", "no stack in the output:\n%s", out)
}

func TestACleanTickIsUntouched(t *testing.T) {
	var errOut strings.Builder
	want := formats.Report{Shipped: 3}

	rep, err, panicked := recoverFlush(&errOut, nil, func() (formats.Report, error) {
		return want, nil
	})

	require.Truef(t, !panicked && err == nil, "clean tick: panicked=%v err=%v", panicked, err)
	assert.Equalf(t, want.Shipped, rep.Shipped, "report was altered: %+v", rep)
	assert.Equalf(t, "", errOut.String(), "a clean tick wrote to stderr: %q", errOut.String())
}

// A run that shipped nothing has no backlog worth chasing, whatever Truncated says; per-file
// failures return no error.
func TestARunThatShippedNothingWaitsTheFullInterval(t *testing.T) {
	rep := formats.Report{Truncated: true, Failed: 64, Shipped: 0}
	require.Equal(t, config.DefaultTick, app.NextDelay(rep, nil, config.DefaultTick))
}
