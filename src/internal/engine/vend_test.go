package engine_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

// The upload path: bounded authorization groups, unconditional PUTs, per-object commits, run
// through the real loop against fakePort.

func workers(compute, upload int) func(*engine.Options) {
	return func(o *engine.Options) { o.Workers, o.UploadWorkers = compute, upload }
}

// Every batch is bounded; each key uploads once, receives a durable fingerprint, and a second run
// finds everything unchanged.
func TestUploadBatchContract(t *testing.T) {
	for _, tc := range []struct{ files, workers, uploadWorkers int }{
		{5, 4, 0}, {6, 1, 1}, {40, 8, 0}, {96, 8, 3},
	} {
		t.Run(fmt.Sprintf("files=%d,workers=%d", tc.files, tc.workers), func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscripts("p/v%03d.jsonl", tc.files)
			f.plan.MaxFilesPerRun = max(64, tc.files)
			rep := f.run(workers(tc.workers, tc.uploadWorkers))
			require.Equal(t, tc.files, rep.Shipped)
			require.Zero(t, rep.Failed)
			sizes, total := f.port.sizes(), 0
			if tc.files == 5 {
				assert.Equal(t, []int{5}, sizes, "a small run fits in one authorization")
			} else {
				require.GreaterOrEqual(t, len(sizes), 2)
			}
			for _, n := range sizes {
				assert.LessOrEqual(t, n, 32, "authorization object bound")
				total += n
			}
			assert.Equal(t, tc.files, total, sizes)
			f.port.storedOnce(t)
			assert.Len(t, f.port.keys(), tc.files)
			assert.Equal(t, tc.files, f.store.Len())
			for _, fo := range rep.Sources[0].Files {
				_, ok := f.store.Get(engine.Key{SourceID: fo.SourceID, NativePath: fo.NativePath})
				require.True(t, ok, "%s committed no fingerprint", fo.RelPath)
			}
			again := f.run(workers(tc.workers, tc.uploadWorkers))
			assert.Truef(t, again.Unchanged == tc.files && again.Shipped == 0, "second pass: %+v", again)
		})
	}
}

// One object's failure is its own. Its siblings commit, and the next run re-prepares only it.
func TestAFailedObjectDoesNotDiscardItsSiblings(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/bad.jsonl", line1)
	f.writeTranscripts("p/ok%02d.jsonl", 4)
	// Whichever file the first group starts with: keys are keyed hashes, not pickable by name.
	var failed string
	f.port.verdict = func(call, idx int, o engine.PreparedObject) error {
		if call == 0 && idx == 0 {
			failed = o.Key
			return errors.New("upload: object store answered HTTP 500")
		}
		return nil
	}

	rep := f.run(workers(4, 0))
	assert.Truef(t, rep.Shipped == 4 && rep.Failed == 1, "want 4 shipped and 1 failed, got %d and %d", rep.Shipped, rep.Failed)
	assert.Equalf(t, 0, rep.Parked, "%d objects parked; an unconditional PUT has no precondition to park on", rep.Parked)

	f.port = newPort()
	rep2 := f.run()
	assert.Truef(t, rep2.Shipped == 1 && rep2.Unchanged == 4, "second run shipped %d and left %d unchanged, want 1 and 4", rep2.Shipped, rep2.Unchanged)
	if got := f.port.groups; len(got) != 1 || len(got[0]) != 1 || got[0][0] != failed {
		t.Errorf("second run authorized %v; only the failed object had anything to send", got)
	}
}

// A refused install is the kill path: admission stops, and the duplicates in flight are one fact.
func TestARefusedAuthorizationStopsTheRun(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/r%02d.jsonl", 20)
	f.port.verdict = always(fmt.Errorf("backend: refused: %w", formats.ErrCredentialsRefused))
	beat := 0

	rep, err := f.try(workers(4, 0), func(o *engine.Options) {
		o.Heartbeat = func(context.Context, engine.Report) error { beat++; return nil }
	})

	require.ErrorIsf(t, err, formats.ErrCredentialsRefused, "want a refusal from the run, got %v", err)
	assert.Equalf(t, 1, rep.Failed, "%d refusals counted; duplicates are the same fact about the same install", rep.Failed)
	assert.Equalf(t, 0, beat, "the heartbeat ran %d times after a refusal", beat)
	assert.Equalf(t, 0, rep.Shipped, "%d objects shipped against a refused install", rep.Shipped)
	assert.Equal(t, 0, f.port.putCount())
	if got := len(f.port.sizes()); got >= 20 {
		t.Errorf("%d authorizations against a revoked install; admission never stopped", got)
	}
}

// An ordinary upload error is per-object: the run continues and attempts every file.
func TestAnOrdinaryUploadErrorDoesNotStopTheRun(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/b%02d.jsonl", 5)
	f.port.verdict = always(errors.New("connection reset by peer"))
	rep := f.run()
	assert.Equalf(t, 5, rep.Failed, "want all 5 attempted and failed, got %+v", rep)
	assert.Empty(t, f.port.keys())
}

// Unavailability counts once, commits nothing, and leaves the install able to retry next run.
func TestUnavailableUploadGroups(t *testing.T) {
	for _, tc := range []struct{ files, workers, status int }{{12, 4, 409}, {40, 8, 503}} {
		t.Run(fmt.Sprintf("HTTP_%d", tc.status), func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscripts("p/u%02d.jsonl", tc.files)
			f.port.verdict = always(fmt.Errorf("backend: HTTP %d: %w", tc.status, engine.ErrUploadUnavailable))
			rep, err := f.try(workers(tc.workers, 0))
			require.ErrorIs(t, err, engine.ErrUploadUnavailable)
			require.NotErrorIs(t, err, formats.ErrCredentialsRefused)
			assert.Equal(t, 1, rep.Failed, "one halted run is one fact")
			assert.Zero(t, rep.Shipped)
			assert.Zero(t, f.store.Len())
			f.port = newPort()
			assert.Equal(t, tc.files, f.run(workers(tc.workers, 0)).Shipped)
			f.port.storedOnce(t)
		})
	}
}

// Only one reauthorization is allowed; commit requires that attempt to succeed.
func TestExpiredTicketRetryContract(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired_twice=%t", expired), func(t *testing.T) {
			f := newFixture(t)
			path := f.writeTranscript("p/e.jsonl", line1)
			f.port.verdict = func(call, _ int, _ engine.PreparedObject) error {
				if call == 0 || expired {
					return fmt.Errorf("upload: HTTP 403: %w", engine.ErrTicketExpired)
				}
				return nil
			}
			rep := f.run()
			shipped := 1
			if expired {
				shipped = 0
			}
			assert.Equal(t, shipped, rep.Shipped)
			assert.Equal(t, 1-shipped, rep.Failed)
			assert.Len(t, f.port.sizes(), 2)
			_, committed := f.store.Get(engine.Key{SourceID: "claude-code-transcripts", NativePath: path})
			assert.Equal(t, !expired, committed)
			f.port.storedOnce(t)
		})
	}
}

// A refused or unavailable enricher group commits nothing for itself while raw objects keep their
// commits, stops the remaining enrichers, and comes back out of engine.Run.
func TestAStoppedDerivedGroupStopsTheSource(t *testing.T) {
	for _, stop := range []error{engine.ErrUploadUnavailable, formats.ErrCredentialsRefused} {
		t.Run(stop.Error(), func(t *testing.T) {
			f := newFixture(t)
			db := cursorFixture(t, f)
			// Call 0 is the raw pass; the enricher's group is what gets stopped.
			f.port.verdict = func(call, _ int, _ engine.PreparedObject) error {
				if call == 0 {
					return nil
				}
				return fmt.Errorf("backend: %w", stop)
			}
			// Sorted after cursor-transcript-join, because enrichers run in id order.
			second := &countingEnricher{id: "zz-never-runs"}
			o := enrichOpts(t, f, db, true)
			o.Enrichers = transforms.NewRegistry(&fixtureEnricher{Enricher: cursorjoin.New(), db: db}, second)
			o.Plan.Sources[0].Enrichers[second.id] = true

			rep, err := engine.Run(context.Background(), f.store, o)
			require.ErrorIs(t, err, stop)
			if stop == engine.ErrUploadUnavailable {
				assert.NotErrorIs(t, err, formats.ErrCredentialsRefused, "an unavailable control plane killed the install")
			}
			assert.Equalf(t, 0, second.calls, "the second enricher ran %d time(s) after the first stopped", second.calls)
			assert.Equalf(t, 1, rep.Shipped, "shipped %d; the raw object ships and the derived one does not", rep.Shipped)
			assert.Equal(t, 1, f.store.Len(), "only the raw object commits")
			derived := 0
			for _, fo := range rep.Sources[0].Files {
				if fo.Derived {
					derived++
					assert.Equal(t, formats.DecisionFailed, fo.Decision)
				}
			}
			assert.Equal(t, 1, derived)
		})
	}
}

// countingEnricher derives nothing and records whether it was asked to.
type countingEnricher struct {
	id    string
	calls int
}

func (e *countingEnricher) ID() string             { return e.id }
func (e *countingEnricher) Version() int           { return 1 }
func (e *countingEnricher) Table() string          { return "" }
func (e *countingEnricher) Keyspaces() []string    { return nil }
func (e *countingEnricher) DBCandidates() []string { return nil }
func (e *countingEnricher) NeedsUnits() bool       { return true }
func (e *countingEnricher) Enrich(transforms.Input) transforms.EnrichResult {
	e.calls++
	return transforms.EnrichResult{EnricherID: e.id, Version: 1}
}
