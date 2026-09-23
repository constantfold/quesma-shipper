package app

// The install's failure record, carried by heartbeats: persisted when the disk allows, held in memory
// when not, and a failed tick ships its own heartbeat, so a machine failing every tick is not read as idle.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

const (
	lastFailureFile = "last-failure.json"
	maxFailureBytes = 1 << 16
)

// JudgeTick persists whether a flush failed and returns the error to judge the run by: lock contention
// becomes nil (another flush is running), and a nil error with every upload failed becomes a failure
// (a real outage). A local failure ships a heartbeat, blocking up to failureHeartbeatTimeout.
// Best-effort: bookkeeping must never change a run's outcome.
func (r *Runtime) JudgeTick(err error, rep formats.Report, panicked bool, mem platform.Delta) error {
	kind := formats.FailureTick
	if panicked {
		kind = formats.FailurePanic
	}
	return r.judge(err, rep, kind, mem)
}

// JudgeFinalSlice judges the SIGTERM drain under its own kind: a failed last slice is loss, not a retry.
func (r *Runtime) JudgeFinalSlice(err error, rep formats.Report, mem platform.Delta) error {
	return r.judge(err, rep, formats.FailureShutdown, mem)
}

func (r *Runtime) judge(err error, rep formats.Report, kind string, mem platform.Delta) error {
	if errors.Is(err, engine.ErrLocked) {
		return nil
	}
	if err == nil && rep.Shipped == 0 && rep.Failed > 0 {
		// A count alone cannot tell a refused PUT from an unreachable control plane, and identical messages are unactionable.
		err = fmt.Errorf("the run shipped nothing: all %d attempted uploads failed: %s",
			rep.Failed, firstFailureReason(rep))
	}

	r.persistRecord("tick outcome", os.Stderr, func(rec *formats.FailureRecord) {
		rec.Facts = r.runFacts(rep, mem)

		// Recorded, never counted: the discard costs a re-ship, but it can otherwise lose a file for good.
		if rep.StoreCorrupt {
			rec.Append(newEvent(r.eff.StateDir, r.runID, formats.FailureStoreCorrupt,
				"the fingerprint store could not be loaded and was discarded; the next sync replaces it"))
		}

		if err == nil {
			// Persisted on a clean run too: it is the next run's baseline, and the next heartbeat is
			// built mid-flush before judging, so it can only read these facts off disk.
			rec.ConsecutiveFailures = 0
		} else {
			ev := newEvent(r.eff.StateDir, r.runID, kind, err.Error())
			rec.Append(ev)
			if ev.Counted() {
				rec.ConsecutiveFailures++
			}
		}
	})

	if err == nil {
		// For the stall heartbeat, which fires mid-tick before a fresh report exists.
		r.lastRep = rep
	}

	// The engine heartbeats only on success; waiting for a healthy run could wait forever. Skipped when uploads failed
	// (it would only stall the loop one more timeout) and on the SIGTERM drain, whose host is leaving.
	if err != nil && kind != formats.FailureShutdown && rep.Failed == 0 {
		r.shipFailureHeartbeat(context.Background(), rep, "failure record", os.Stderr)
	}
	return err
}

const failureHeartbeatTimeout = 30 * time.Second

// shipFailureHeartbeat never mirrors: doctor reads heartbeat.json as the last real flush.
// A cancelled parent (the tick finished mid-send) is not worth a warning.
func (r *Runtime) shipFailureHeartbeat(parent context.Context, rep formats.Report, what string, errOut io.Writer) {
	if r.upload == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, failureHeartbeatTimeout)
	defer cancel()
	if err := r.writeHeartbeat(ctx, rep, false); err != nil && parent.Err() == nil {
		fmt.Fprintf(errOut, "warning: could not ship the %s: %v\n", what, err)
	}
}

// The record survives in memory even when its write does not, so readers must come through here.
func (r *Runtime) loadRecordLocked() *formats.FailureRecord {
	if r.rec == nil {
		rec := readFailureRecord(r.eff.StateDir)
		r.rec = &rec
	}
	return r.rec
}

// persistRecord keeps the in-memory copy only while the disk refuses writes, so the next mutation
// re-reads the file and merges other processes' events. It writes outside the lock, so an fsync
// wedged on a failing disk cannot block the heartbeat, which reads the record under the same mutex.
func (r *Runtime) persistRecord(what string, errOut io.Writer, mutate func(*formats.FailureRecord)) {
	r.recMu.Lock()
	rec := r.loadRecordLocked()
	mutate(rec)
	snapshot := *rec
	snapshot.Recent = append([]formats.FailureEvent(nil), rec.Recent...)
	r.recMu.Unlock()

	if err := writeFailureRecord(r.eff.StateDir, snapshot); err != nil {
		fmt.Fprintf(errOut, "warning: could not record the %s: %v\n", what, err)
		return
	}
	r.recMu.Lock()
	r.rec = nil
	r.recMu.Unlock()
}

// WatchStalledTick reports a tick that outlives its interval, since a stuck run never reaches the judge.
// One event is refreshed per fire, and intervals double, so a fleet-wide stall is no request storm.
func (r *Runtime) WatchStalledTick(ctx context.Context, n int, every time.Duration, errOut io.Writer) {
	if every <= 0 {
		return
	}
	started := time.Now()
	for wait := every; ; wait *= 2 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		elapsed := time.Since(started).Round(time.Second)
		fmt.Fprintf(errOut, "warning: tick %d still running after %s\n", n, elapsed)
		r.persistRecord("stalled tick", errOut, func(rec *formats.FailureRecord) {
			e := newEvent(r.eff.StateDir, r.runID, formats.FailureStalled,
				fmt.Sprintf("tick %d still running after %s", n, elapsed))
			// Replaced: clean ticks append nothing, so a later stall must not hide behind a stale one.
			if last := rec.Latest(); last != nil && last.Kind == formats.FailureStalled {
				*last = e
			} else {
				rec.Append(e)
			}
		})
		// This overwrites the remote heartbeat; blank per-source health would read as an idle install.
		r.shipFailureHeartbeat(ctx, r.lastRep, "stall heartbeat", errOut)
	}
}

// RecordCrash persists how the previous run died, as found by the run after it.
func RecordCrash(crash *formats.LastCrash) {
	if crash == nil {
		return
	}
	appendWithoutRuntime("crash", func(dir string, rec *formats.FailureRecord) bool {
		// One event per dead run: it is re-detected each start until delivered, and duplicates evict the log.
		for i := len(rec.Recent) - 1; i >= 0; i-- {
			if rec.Recent[i].Kind == formats.FailureCrash {
				if rec.Recent[i].RunID == crash.RunID {
					return false
				}
				break
			}
		}
		// Uncounted: crashes keep their own counter, reset by delivery rather than by success.
		rec.Append(newEvent(dir, crash.RunID, formats.FailureCrash, fmt.Sprintf(
			"previous run never exited: last step %q; %d consecutive unclean run(s)", crash.Phase, crash.Consecutive)))
		return true
	})
}

// runFacts snapshots what the run cost and was allowed to do, on every outcome so runs compare.
func (r *Runtime) runFacts(rep formats.Report, mem platform.Delta) *formats.RunFacts {
	return &formats.RunFacts{
		GOMAXPROCS:       runtime.GOMAXPROCS(0),
		MaxFilesPerRun:   r.eff.MaxFilesPerRun,
		MaxInFlightBytes: platform.MaxInFlightBytes(),
		SoftLimitBytes:   platform.SoftLimit(),
		HeapInuseBytes:   mem.After.HeapInuse,
		SysBytes:         mem.After.Sys,
		GCCycles:         mem.After.NumGC - mem.Before.NumGC,

		SlowestScrubNanos: rep.SlowestScrubNanos,
		SlowestScrubBytes: rep.SlowestScrubBytes,
	}
}

// RecordPanic persists a panic from any verb, even without resolved config. Uncounted: the count is of
// collection runs. The stack stays on stderr since it can carry payload-derived strings.
func RecordPanic(verb string, cause any) {
	recordWithoutRuntime("", formats.FailurePanic, fmt.Sprintf("panic in %s: %v", verb, cause))
}

// RecordStartupFailure persists a collecting run that could not build its Runtime, so JudgeTick cannot.
func RecordStartupFailure(verb, runID string, cause error) {
	if cause == nil {
		return
	}
	recordWithoutRuntime(runID, formats.FailureInit,
		fmt.Sprintf("%s could not start: %v", verb, cause))
}

// RecordUpdateFailure persists a failed self-update, uncounted since collection still works. Self-update
// is the remediation channel, and a supervised daemon's stderr is a log file nothing ships.
func RecordUpdateFailure(message string) {
	recordWithoutRuntime("", formats.FailureUpdate, message)
}

func recordWithoutRuntime(runID, kind, message string) {
	appendWithoutRuntime("failure", func(dir string, rec *formats.FailureRecord) bool {
		ev := newEvent(dir, runID, kind, message)
		rec.Append(ev)
		if ev.Counted() {
			rec.ConsecutiveFailures++
		}
		return true
	})
}

// appendWithoutRuntime resolves the state dir like the kill switch, so a config too broken to load
// cannot also hide the record of what broke.
func appendWithoutRuntime(what string, mutate func(dir string, rec *formats.FailureRecord) bool) {
	dir, _, err := pauseStateDir()
	if err != nil || dir == "" {
		return
	}
	// A verb can fail before an identity exists, so the directory may not either.
	if err := platform.EnsureDir(dir, 0o700); err != nil {
		return
	}
	rec := readFailureRecord(dir)
	if !mutate(dir, &rec) {
		return
	}
	if err := writeFailureRecord(dir, rec); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the %s: %v\n", what, err)
	}
}

// The username placeholder is applied here, not at call sites, so no route to the record forgets it.
func newEvent(stateDir, runID, kind, message string) formats.FailureEvent {
	return formats.FailureEvent{
		At:      time.Now().UTC().Format(time.RFC3339),
		Kind:    kind,
		RunID:   runID,
		Message: formats.ApplyUserPlaceholder(message, engine.UsernameFromStateDir(stateDir)),
	}
}

// What the heartbeat carries: the in-memory failures, plus the crash read out of the journal.
func (r *Runtime) failureRecord() formats.FailureRecord {
	r.recMu.Lock()
	rec := *r.loadRecordLocked()
	rec.Recent = append([]formats.FailureEvent(nil), rec.Recent...)
	r.recMu.Unlock()
	rec.LastCrash = r.lastCrash
	return rec
}

// An unparsable record is reported and treated as absent: bookkeeping must not stop a flush.
func readFailureRecord(stateDir string) formats.FailureRecord {
	raw, _, err := platform.ReadWhole(filepath.Join(stateDir, lastFailureFile), maxFailureBytes)
	if err != nil {
		// errors.Is because ReadWhole wraps the open error; a missing record is normal.
		if !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: %s is unreadable and is ignored: %v\n", lastFailureFile, err)
		}
		return formats.FailureRecord{}
	}
	var rec formats.FailureRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s does not parse and is ignored: %v\n", lastFailureFile, err)
		return formats.FailureRecord{}
	}
	return rec
}

// All uploads almost always fail the same way, and the audit log has the rest.
func firstFailureReason(rep formats.Report) string {
	for _, s := range rep.Sources {
		for _, f := range s.Files {
			if f.Decision == formats.DecisionFailed && f.Reason != "" {
				return f.Reason
			}
		}
	}
	return "no reason recorded"
}

func writeFailureRecord(stateDir string, rec formats.FailureRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return platform.WriteAtomic(filepath.Join(stateDir, lastFailureFile), body, 0o600)
}
