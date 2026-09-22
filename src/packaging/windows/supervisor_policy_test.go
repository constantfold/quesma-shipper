package windows

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

type decision struct {
	delay   time.Duration
	crashes int
	restart bool
}

func policy(exitCode int, uptime time.Duration, crashes int) decision {
	delay, next, restart := restartPolicy(exitCode, uptime, crashes)
	return decision{delay, next, restart}
}

func TestSupervisorRestartPolicy(t *testing.T) {
	require.Equal(t, decision{0, 0, true}, policy(common.SupervisorRestartExitCode, 0, 7), "intentional restart")
	for i, delay := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
		8 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		require.Equal(t, decision{delay, i + 1, true}, policy(1, 0, i), "crash %d", i+1)
	}
	require.Equal(t, decision{0, maxCrashCount, false}, policy(1, 0, maxCrashCount-1), "give-up")
}

func TestAHealthyRunResetsTheCrashBudget(t *testing.T) {
	require.Equal(t, decision{firstCrashDelay, 1, true}, policy(1, healthyUptime, maxCrashCount-1), "after a healthy run")
	require.False(t, policy(1, healthyUptime-time.Second, maxCrashCount-1).restart, "a short run must still exhaust the budget")
}
