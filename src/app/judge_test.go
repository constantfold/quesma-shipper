package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Classification, recovery and restart share one history; every event keeps its originating run.
func TestJudgeTickLifecycle(t *testing.T) {
	const first, second = "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	r := &Runtime{eff: &config.Effective{StateDir: t.TempDir()}}
	allFailed := formats.Report{Failed: 3, Sources: []formats.SourceOutcome{{Files: []formats.FileOutcome{
		{Decision: formats.DecisionFailed, Reason: "the control plane authorized nothing"},
	}}}}
	var history []formats.FailureEvent
	for _, tc := range []struct {
		name, runID   string
		err           error
		report        formats.Report
		panicked      bool
		streak        int
		kind, message string
	}{
		{"locked", first, fmt.Errorf("open store: %w", engine.ErrLocked), formats.Report{}, false, 0, "", ""},
		{"failed", first, errors.New("flush failed"), formats.Report{}, false, 1, formats.FailureTick, "flush failed"},
		{"panicked", second, errors.New("still failing"), formats.Report{}, true, 2, formats.FailurePanic, "still failing"},
		{"empty recovery", second, nil, formats.Report{}, false, 0, "", ""},
		{"sink refused", first, errors.New("the sink refused"), formats.Report{}, false, 1, formats.FailureTick, "the sink refused"},
		{"partial recovery", second, nil, formats.Report{Shipped: 1, Failed: 3}, false, 0, "", ""},
		{"all failed", first, nil, allFailed, false, 1, formats.FailureTick,
			"the run shipped nothing: all 3 attempted uploads failed: the control plane authorized nothing"},
		{"later failure", second, errors.New("the sink refused every object"), formats.Report{}, false, 2,
			formats.FailureTick, "the sink refused every object"},
		{"shipped recovery", second, nil, formats.Report{Shipped: 1}, false, 0, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.runID = tc.runID
			err := r.JudgeTick(tc.err, tc.report, tc.panicked, platform.Delta{})
			if tc.kind == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.message)
				history = append(history, formats.FailureEvent{RunID: tc.runID, Kind: tc.kind, Message: tc.message})
			}
			rec := readFailureRecord(r.eff.StateDir)
			later := &Runtime{eff: r.eff}
			assert.Equal(t, rec, later.failureRecord(), "a new runtime must load the persisted history")
			assert.Equal(t, tc.streak, rec.ConsecutiveFailures)
			for i := range rec.Recent {
				assert.NotEmpty(t, rec.Recent[i].At)
				rec.Recent[i].At = ""
			}
			assert.Equal(t, history, rec.Recent)
		})
	}
}

func TestJudgeTickPlaceholdersTheUsername(t *testing.T) {
	dir := t.TempDir()
	name := engine.UsernameFromStateDir(dir)
	if name == "" {
		t.Skip("no resolvable username on this machine")
	}
	r := &Runtime{eff: &config.Effective{StateDir: dir}}
	r.JudgeTick(fmt.Errorf("open /Users/%s/transcript.jsonl: permission denied", name), formats.Report{}, false, platform.Delta{})
	rec := readFailureRecord(r.eff.StateDir)
	require.True(t, rec.Latest() != nil, "no failure recorded")
	assert.NotContainsf(t, rec.Latest().Message, "/"+name+"/", "the persisted message still carries the username: %q", rec.Latest().Message)
}

// Keep the newest events within the heartbeat's fixed history limit.
func TestTheFailureLogIsBoundedAndKeepsTheNewest(t *testing.T) {
	r := &Runtime{eff: &config.Effective{StateDir: t.TempDir()}}

	for i := range formats.MaxRecentFailures + 15 {
		r.JudgeTick(fmt.Errorf("failure number %d", i), formats.Report{}, false, platform.Delta{})
	}

	rec := readFailureRecord(r.eff.StateDir)
	require.Lenf(t, rec.Recent, formats.MaxRecentFailures, "the log holds %d events, want the cap of %d", len(rec.Recent), formats.MaxRecentFailures)
	// Oldest first, so the last element is the newest failure.
	assert.Equal(t, rec.Latest().Message, fmt.Sprintf("failure number %d", formats.MaxRecentFailures+14))
	assert.Equal(t, rec.Recent[0].Message, fmt.Sprintf("failure number %d", 15))
	// The count is not the log's length: it counts runs since the last success, unbounded.
	assert.Equalf(t, formats.MaxRecentFailures+15, rec.ConsecutiveFailures, "consecutive_failures = %d, want every failed run counted", rec.ConsecutiveFailures)
}

// These failures must persist even when configuration cannot produce a Runtime.
func TestFailuresWithoutResolvedConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record func()
		want   formats.FailureEvent
		count  int
	}{
		{"panic", func() { RecordPanic("enroll", "runtime error: index out of range [3] with length 0") },
			formats.FailureEvent{Kind: formats.FailurePanic,
				Message: "panic in enroll: runtime error: index out of range [3] with length 0"}, 0},
		{"startup", func() { RecordStartupFailure("sync", "cccccccccccccccc", errors.New("unparseable")) },
			formats.FailureEvent{Kind: formats.FailureInit, RunID: "cccccccccccccccc",
				Message: "sync could not start: unparseable"}, 1},
		{"update", func() { RecordUpdateFailure("self-update from 1.2.3 did not happen: tuf: no such target") },
			formats.FailureEvent{Kind: formats.FailureUpdate,
				Message: "self-update from 1.2.3 did not happen: tuf: no such target"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			stateDir, err := StateDirWithoutConfig()
			if err != nil {
				t.Skipf("no resolvable state directory here: %v", err)
			}
			tc.record()
			rec := readFailureRecord(stateDir)
			require.NotNil(t, rec.Latest(), "the failure was not persisted under %s", stateDir)
			got := *rec.Latest()
			assert.NotEmpty(t, got.At)
			got.At = ""
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.count, rec.ConsecutiveFailures)
		})
	}
}

// Re-enrollment clears the prior failure streak while retaining the discard warning.
func TestARecoveringRunClearsTheStreakItInherited(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		r := &Runtime{eff: &config.Effective{StateDir: dir}, runID: "aaaaaaaaaaaaaaaa"}
		r.JudgeTick(errors.New("state: document belongs to another install"), formats.Report{}, false, platform.Delta{})
	}
	require.Equal(t, 3, readFailureRecord(dir).ConsecutiveFailures)

	r := &Runtime{eff: &config.Effective{StateDir: dir}, runID: "bbbbbbbbbbbbbbbb"}
	require.NoError(t, r.JudgeTick(nil, formats.Report{StoreCorrupt: true, Shipped: 7}, false, platform.Delta{}))

	rec := readFailureRecord(dir)
	assert.Equalf(t, 0, rec.ConsecutiveFailures, "the recovery left %d failures on the streak", rec.ConsecutiveFailures)
	require.True(t, rec.Latest() != nil && rec.Latest().Kind == formats.FailureStoreCorrupt, "the discard was not recorded: %+v", rec.Recent)
	last := rec.LatestCounted()
	assert.True(t, last != nil && last.Kind == formats.FailureTick, "LatestCounted picked the uncounted discard: %+v", last)
	assert.Nil(t, failureRows(dir, time.Now()), "doctor still reports failing runs after the recovery")
}

func TestACrashIsPersistedLocally(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	stateDir, err := StateDirWithoutConfig()
	if err != nil {
		t.Skipf("no resolvable state directory here: %v", err)
	}

	RecordCrash(&formats.LastCrash{RunID: "dddddddddddddddd", Phase: "tick 3", Consecutive: 2})

	rec := readFailureRecord(stateDir)
	latest := rec.Latest()
	require.Truef(t, latest != nil && latest.Kind == formats.FailureCrash, "the crash was not persisted: %+v", rec)
	assert.Truef(t, latest.RunID == "dddddddddddddddd" && strings.Contains(latest.Message, `"tick 3"`), "the event does not attribute the dead run: %+v", latest)
	// Crashes keep their own counter; the collection count must not move.
	assert.Equalf(t, 0, rec.ConsecutiveFailures, "a crash moved consecutive_failures to %d", rec.ConsecutiveFailures)

	// An undelivered crash is re-detected on every restart; only a NEW dead run may append.
	RecordCrash(&formats.LastCrash{RunID: "dddddddddddddddd", Phase: "tick 3", Consecutive: 3})
	require.Len(t, readFailureRecord(stateDir).Recent, 1)
	RecordCrash(&formats.LastCrash{RunID: "ffffffffffffffff", Phase: "init", Consecutive: 2})
	require.Len(t, readFailureRecord(stateDir).Recent, 2)
}

// Repeated stall warnings must not evict other failures from the bounded log.
func TestStalledTickLifecycle(t *testing.T) {
	dir := t.TempDir()
	r := &Runtime{eff: &config.Effective{StateDir: dir}, runID: "eeeeeeeeeeeeeeee"}
	watchFires(r, 7, 2)

	rec := readFailureRecord(dir)
	require.Truef(t, len(rec.Recent) == 1 && rec.Latest().Kind == formats.FailureStalled, "want exactly one stalled event, got %+v", rec.Recent)
	assert.True(t, strings.Contains(rec.Latest().Message, "tick 7") && rec.Latest().RunID == "eeeeeeeeeeeeeeee", "the event does not name the tick or its run: %+v", rec.Latest())
	assert.Equalf(t, 0, rec.ConsecutiveFailures, "a stall moved consecutive_failures to %d; the tick may yet complete", rec.ConsecutiveFailures)

	// Clean ticks append nothing; the next stall must replace the standing event.
	for range 3 {
		r.JudgeTick(nil, formats.Report{Shipped: 1}, false, platform.Delta{})
	}
	watchFires(r, 900, 1)
	rec = readFailureRecord(dir)
	require.Len(t, rec.Recent, 1)
	assert.Contains(t, rec.Latest().Message, "tick 900")
}

// Wait for actual watchdog warnings rather than guessing how long the goroutine needs.
type fires chan struct{}

func (c fires) Write(p []byte) (int, error) { c <- struct{}{}; return len(p), nil }

func watchFires(r *Runtime, n, want int) {
	ctx, cancel := context.WithCancel(context.Background())
	fired := make(fires, 16)
	done := make(chan struct{})
	go func() {
		r.WatchStalledTick(ctx, n, time.Millisecond, fired)
		close(done)
	}()
	for i := 0; i < want; i++ {
		<-fired
	}
	cancel()
	<-done
}

// Successful writes must release the fallback record so other processes' events remain visible.
func TestJudgeMergesEventsFromOtherWriters(t *testing.T) {
	dir := t.TempDir()
	r := &Runtime{eff: &config.Effective{StateDir: dir}}
	r.JudgeTick(errors.New("boom"), formats.Report{}, false, platform.Delta{})

	other := readFailureRecord(dir)
	other.Append(formats.FailureEvent{At: "2026-01-01T00:00:00Z", Kind: formats.FailureUpdate, Message: "tuf: no such target"})
	require.NoError(t, writeFailureRecord(dir, other))

	r.JudgeTick(nil, formats.Report{Shipped: 1}, false, platform.Delta{})
	rec := readFailureRecord(dir)
	require.Lenf(t, rec.Recent, 2, "the other writer's event was clobbered: %+v", rec.Recent)
}

// Clean runs also persist resource costs, providing a baseline without adding failure events.
func TestTheFactsRideACleanRunToo(t *testing.T) {
	dir := t.TempDir()
	r := &Runtime{eff: &config.Effective{StateDir: dir, MaxFilesPerRun: 512}}
	mem := platform.Delta{
		Before: platform.Sample{HeapInuse: 1 << 20, NumGC: 5},
		After:  platform.Sample{HeapInuse: 9 << 20, Sys: 40 << 20, NumGC: 12},
	}

	r.JudgeTick(nil, formats.Report{SlowestScrubNanos: 2_500_000, SlowestScrubBytes: 4096}, false, mem)

	f := readFailureRecord(dir).Facts
	require.True(t, f != nil, "a clean run recorded no facts, so there is no baseline to compare against")
	assert.Truef(t, f.HeapInuseBytes == 9<<20 && f.SysBytes == 40<<20, "memory not carried: heap %d sys %d", f.HeapInuseBytes, f.SysBytes)
	// The delta, not the absolute: GC cycles rise sharply as the heap nears the limit.
	assert.Equalf(t, uint32(7), f.GCCycles, "gc cycles = %d, want the delta 7", f.GCCycles)
	assert.Truef(t, f.SlowestScrubNanos == 2_500_000 && f.SlowestScrubBytes == 4096, "the slowest redaction did not travel: %d ns over %d bytes", f.SlowestScrubNanos, f.SlowestScrubBytes)
	assert.Truef(t, f.MaxFilesPerRun == 512 && f.GOMAXPROCS != 0 && f.MaxInFlightBytes != 0, "the concurrency configuration is incomplete: %+v", f)
}
