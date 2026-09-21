package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSpec() Spec {
	return Spec{Executable: "/usr/local/bin/quesma-shipper", Args: []string{"run"},
		Home: "/Users/jane", StateDir: "/Users/jane/.local/state/trajectory-shipper",
		LogDir: "/Users/jane/.local/state/trajectory-shipper/logs"}
}

func TestRunMarkerRoundTrips(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 7, 30, 10, 30, 0, 0, time.UTC)
	require.NoError(t, RecordRun(dir, at))
	if got := LastRun(dir); !got.Equal(at) {
		t.Errorf("last run = %s, want %s", got, at)
	}
}

func TestACorruptRunMarkerReadsAsNever(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, RunMarker), []byte("yesterday\n"), 0o644))
	assert.True(t, LastRun(dir).IsZero(), "a corrupt marker was parsed as a real timestamp")
}

func TestInstallSpecRequiresAnAbsoluteExecutable(t *testing.T) {
	require.Error(t, ValidateInstall(Spec{Executable: "quesma-shipper"}), "a relative executable path was accepted")
	require.Error(t, ValidateInstall(Spec{}), "an empty spec was accepted")
}

func TestCronHintUsesOneShotRunAndConfiguredTick(t *testing.T) {
	spec := testSpec()
	spec.Tick = 5 * time.Minute
	got := CronHint(spec)
	assert.Truef(t, strings.HasPrefix(got, "*/5 * * * * ") && strings.Contains(got, " run --once"), "unexpected cron hint: %q", got)
}

func TestCronRoundsUpUnsupportedIntervals(t *testing.T) {
	cases := map[time.Duration]string{0: "*/15 * * * *", 30 * time.Second: "* * * * *",
		90 * time.Second: "*/2 * * * *", 25 * time.Hour: "0 0 * * *"}
	for tick, want := range cases {
		assert.Equal(t, cronExpr(tick), want)
	}
}
