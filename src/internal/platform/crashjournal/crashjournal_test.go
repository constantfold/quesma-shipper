package crashjournal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A killed process leaves entries without an exit; its PID must not match the live test process.
func deadRun(t *testing.T, dir, runID string, mark func(l *Log)) {
	t.Helper()
	l, err := Open(dir, runID)
	require.NoError(t, err)
	l.append(entry{Ev: "start", PID: 99999999}, true)
	mark(l)
}

func TestHealthyJournalHasNoCrash(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		finished    bool
	}{
		{"live", "tick 1", false},
		{"clean", "init", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.Nil(t, LastRun(dir), "a fresh state directory has no journal")
			l, err := Open(dir, "run-a")
			require.NoError(t, err)
			l.Start()
			l.Phase(tc.phase)
			if tc.finished {
				l.Exit()
			}
			require.Nil(t, LastRun(dir), "a live or clean run is not a crash")
		})
	}
}

// The phase is the finest attribution a death gets: enough to say a run died mid-tick rather than
// during startup. Every consecutive death counts, and the newest one is reported.
func TestConsecutiveCrashesCounted(t *testing.T) {
	dir := t.TempDir()
	deadRun(t, dir, "run-a", func(l *Log) { l.Phase("init") })
	deadRun(t, dir, "run-b", func(l *Log) { l.Phase("init") })
	deadRun(t, dir, "run-c", func(l *Log) {
		l.Phase("init")
		l.Phase("tick 1")
	})

	s := LastRun(dir)
	require.Truef(t, s != nil && !s.Clean && s.RunID == "run-c" && s.Crashes == 3 && s.Phase == "tick 1", "want run-c with 3 crashes at tick 1, got %+v", s)
}

// Clean restarts cannot clear a crash: only delivery of the crash report does.
func TestCrashSurvivesRestartsUntilReported(t *testing.T) {
	for _, tc := range []struct {
		phase   string
		retries int
	}{{"init", 1}, {"tick 1", 2}} {
		t.Run(tc.phase, func(t *testing.T) {
			dir := t.TempDir()
			deadRun(t, dir, "run-crash", func(l *Log) { l.Phase(tc.phase) })
			want := &Summary{RunID: "run-crash", PID: 99999999, Phase: tc.phase, Crashes: 1}
			require.Equal(t, want, LastRun(dir))
			for _, id := range []string{"run-retry1", "run-retry2"}[:tc.retries] {
				l, err := Open(dir, id)
				require.NoError(t, err)
				l.Start()
				l.Exit()
				require.Equal(t, want, LastRun(dir), "clean restart %s must preserve the pending crash", id)
			}

			l, err := Open(dir, "run-delivery")
			require.NoError(t, err)
			l.Start()
			l.Reported()
			l.Exit()
			require.Nil(t, LastRun(dir), "the delivered crash report must be cleared")
		})
	}
}

func TestTornLastLineTolerated(t *testing.T) {
	dir := t.TempDir()
	deadRun(t, dir, "run-a", func(l *Log) { l.Phase("engine") })
	f, err := os.OpenFile(filepath.Join(dir, fileName), os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, writeStringErr := f.WriteString(`{"at":"2026-01-01T00:00:00Z","run_id":"run-a","ev":"re`)
	require.NoError(t, writeStringErr)
	f.Close()

	s := LastRun(dir)
	require.Truef(t, s != nil && !s.Clean && s.Phase == "engine", "want the last whole entry to win, got %+v", s)
}

func TestOpenRotatesALargeJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	require.NoError(t, os.WriteFile(path, make([]byte, maxLogBytes), 0o600))
	_, openErr := Open(dir, "run-a")
	require.NoError(t, openErr)
	_, statErr := os.Stat(path + ".1")
	require.NoErrorf(t, statErr, "want a rotated generation: %v", statErr)
	if info, err := os.Stat(path); err == nil && info.Size() >= maxLogBytes {
		t.Fatal("current file was not reset")
	}
}

func TestNilLogIsSilent(t *testing.T) {
	var l *Log
	l.Start()
	l.Phase("init")
	l.Reported()
	l.Exit()
}
