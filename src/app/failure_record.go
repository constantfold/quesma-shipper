package app

// Persistent failure records, with an in-memory fallback when writes fail.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

const (
	lastFailureFile = "last-failure.json"
	maxFailureBytes = 1 << 16
)

// The record survives in memory even when its write does not, so readers must come through here.
func (r *Runtime) loadRecordLocked() *formats.FailureRecord {
	if r.rec == nil {
		rec := readFailureRecord(r.eff.StateDir)
		r.rec = &rec
	}
	return r.rec
}

// persistRecord writes outside the mutex, so a wedged fsync cannot block heartbeat readers.
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

// RecordCrash skips the latest crashed run when it is rediscovered on restart before delivery.
func RecordCrash(crash *formats.LastCrash) {
	if crash == nil {
		return
	}
	appendWithoutRuntime("crash", func(dir string, rec *formats.FailureRecord) bool {
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

// RecordPanic records an uncounted, standalone panic; stacks stay on stderr because they may contain payloads.
func RecordPanic(verb string, cause any) {
	recordWithoutRuntime("", formats.FailurePanic, fmt.Sprintf("panic in %s: %v", verb, cause))
}

// RecordStartupFailure covers collection that failed before a Runtime existed.
func RecordStartupFailure(verb, runID string, cause error) {
	if cause == nil {
		return
	}
	recordWithoutRuntime(runID, formats.FailureInit,
		fmt.Sprintf("%s could not start: %v", verb, cause))
}

// RecordUpdateFailure records a failed remediation attempt without counting it as a collection failure.
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

// appendWithoutRuntime resolves state itself, so broken configuration cannot hide its own failure.
func appendWithoutRuntime(what string, mutate func(dir string, rec *formats.FailureRecord) bool) {
	dir, _, err := pauseStateDir()
	if err != nil || dir == "" || platform.EnsureDir(dir, 0o700) != nil {
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

// Apply the username placeholder to every persisted event.
func newEvent(stateDir, runID, kind, message string) formats.FailureEvent {
	return formats.FailureEvent{At: time.Now().UTC().Format(time.RFC3339), Kind: kind, RunID: runID,
		Message: formats.ApplyUserPlaceholder(message, engine.UsernameFromStateDir(stateDir))}
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

// Corrupt bookkeeping must not prevent collection.
func readFailureRecord(stateDir string) formats.FailureRecord {
	raw, _, err := platform.ReadWhole(filepath.Join(stateDir, lastFailureFile), maxFailureBytes)
	if err != nil {
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

func writeFailureRecord(stateDir string, rec formats.FailureRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return platform.WriteAtomic(filepath.Join(stateDir, lastFailureFile), body, 0o600)
}
