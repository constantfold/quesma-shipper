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

// The upload path: bounded authorization groups, unconditional PUTs, per-object commits. Every
// test here runs the real loop against fakePort, which stands in for the whole network leg.

// vendRun runs the loop with the port wired and returns the report and the run's error.
func vendRun(f *fixture, port *fakePort, adjust func(*engine.Options)) (engine.Report, error) {
	o := f.opts()
	o.Upload = port
	if adjust != nil {
		adjust(&o)
	}
	return engine.Run(context.Background(), f.store, o)
}

// Every batch is bounded; each key uploads once and receives a durable fingerprint.
func TestUploadBatchContract(t *testing.T) {
	for _, tc := range []struct {
		files, workers, uploadWorkers int
		pattern                       string
	}{
		{5, 4, 0, "p/v%02d.jsonl"},
		{40, 8, 0, "p/g%02d.jsonl"},
		{96, 8, 3, "p/x%03d.jsonl"},
	} {
		t.Run(fmt.Sprintf("files=%d", tc.files), func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscripts(tc.pattern, tc.files)
			f.eff.MaxFilesPerRun = max(64, tc.files)
			port := newPort()
			rep, err := vendRun(f, port, func(o *engine.Options) {
				o.Workers, o.UploadWorkers = tc.workers, tc.uploadWorkers
			})
			require.NoError(t, err)
			require.Equal(t, tc.files, rep.Shipped)
			sizes, total := port.sizes(), 0
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
			port.storedOnce(t)
			assert.Len(t, port.keys(), tc.files)
			assert.Equal(t, tc.files, f.store.Len())
			for _, fo := range rep.Sources[0].Files {
				_, ok := f.store.Get(engine.Key{SourceID: fo.SourceID, NativePath: fo.NativePath})
				require.True(t, ok, "%s committed no fingerprint", fo.RelPath)
			}
		})
	}
}

// One object's failure is its own. Its siblings commit, and the next run re-prepares only it.
func TestAFailedObjectDoesNotDiscardItsSiblings(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/bad.jsonl", line1)
	f.writeTranscripts("p/ok%02d.jsonl", 4)
	port := newPort()
	// Whichever file the first group starts with: keys are keyed hashes, not pickable by name.
	var failed string
	port.verdict = func(call, idx int, o engine.PreparedObject) error {
		if call == 0 && idx == 0 {
			failed = o.Key
			return errors.New("upload: object store answered HTTP 500")
		}
		return nil
	}

	rep, err := vendRun(f, port, func(o *engine.Options) { o.Workers = 4 })
	require.NoErrorf(t, err, "run: %v", err)
	assert.Truef(t, rep.Shipped == 4 && rep.Failed == 1, "want 4 shipped and 1 failed, got %d and %d", rep.Shipped, rep.Failed)
	assert.Equalf(t, 0, rep.Parked, "%d objects parked; an unconditional PUT has no precondition to park on", rep.Parked)

	// The failure persisted nothing, so the second run re-prepares exactly that one file.
	healthy := newPort()
	rep2, err := vendRun(f, healthy, nil)
	require.NoErrorf(t, err, "second run: %v", err)
	assert.Truef(t, rep2.Shipped == 1 && rep2.Unchanged == 4, "second run shipped %d and left %d unchanged, want 1 and 4", rep2.Shipped, rep2.Unchanged)
	if got := healthy.groups; len(got) != 1 || len(got[0]) != 1 || got[0][0] != failed {
		t.Errorf("second run authorized %v; only the failed object had anything to send", got)
	}
}

// A refused install is the kill path: the run stops and the duplicates in flight are one fact.
func TestARefusedAuthorizationStopsTheRun(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/r%02d.jsonl", 20)
	port := newPort()
	port.verdict = func(int, int, engine.PreparedObject) error {
		return fmt.Errorf("backend: refused: %w", formats.ErrCredentialsRefused)
	}
	beat := 0

	rep, err := vendRun(f, port, func(o *engine.Options) {
		o.Workers = 4
		o.Heartbeat = func(context.Context, engine.Report) error { beat++; return nil }
	})

	require.ErrorIsf(t, err, formats.ErrCredentialsRefused, "want a refusal from the run, got %v", err)
	assert.Equalf(t, 1, rep.Failed, "%d refusals counted; duplicates are the same fact about the same install", rep.Failed)
	assert.Equalf(t, 0, beat, "the heartbeat ran %d times after a refusal", beat)
	assert.Equalf(t, 0, rep.Shipped, "%d objects shipped against a refused install", rep.Shipped)
}

// Unavailability counts once, commits nothing, and leaves the install able to retry next run.
func TestUnavailableUploadGroups(t *testing.T) {
	for _, tc := range []struct {
		files, workers, status int
		pattern                string
	}{
		{12, 4, 409, "p/u%02d.jsonl"},
		{40, 8, 503, "p/m%02d.jsonl"},
	} {
		t.Run(fmt.Sprintf("HTTP_%d", tc.status), func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscripts(tc.pattern, tc.files)
			port := newPort()
			port.verdict = func(int, int, engine.PreparedObject) error {
				return fmt.Errorf("backend: HTTP %d: %w", tc.status, engine.ErrUploadUnavailable)
			}
			workers := func(o *engine.Options) { o.Workers = tc.workers }
			rep, err := vendRun(f, port, workers)
			require.ErrorIs(t, err, engine.ErrUploadUnavailable)
			require.NotErrorIs(t, err, formats.ErrCredentialsRefused)
			assert.Equal(t, 1, rep.Failed, "one halted run is one fact")
			assert.Zero(t, rep.Shipped)
			assert.Zero(t, f.store.Len())
			healthy := newPort()
			rep, err = vendRun(f, healthy, workers)
			require.NoError(t, err)
			assert.Equal(t, tc.files, rep.Shipped)
			healthy.storedOnce(t)
		})
	}
}

// Only one reauthorization is allowed; commit requires that attempt to succeed.
func TestExpiredTicketRetryContract(t *testing.T) {
	for _, tc := range []struct {
		path    string
		expired bool
		shipped int
	}{
		{"p/e0.jsonl", false, 1},
		{"p/e1.jsonl", true, 0},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscript(tc.path, line1)
			port := newPort()
			port.verdict = func(call, _ int, _ engine.PreparedObject) error {
				if call == 0 || tc.expired {
					return fmt.Errorf("upload: HTTP 403: %w", engine.ErrTicketExpired)
				}
				return nil
			}
			rep, err := vendRun(f, port, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.shipped, rep.Shipped)
			assert.Equal(t, 1-tc.shipped, rep.Failed)
			assert.Len(t, port.sizes(), 2)
			_, committed := f.store.Get(engine.Key{SourceID: "claude-code-transcripts",
				NativePath: f.home + "/.claude/projects/" + tc.path})
			assert.Equal(t, tc.shipped == 1, committed)
			port.storedOnce(t)
		})
	}
}

// Preview computes everything that would leave the machine and authorizes nothing.
func TestPreviewAuthorizesNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/d%02d.jsonl", 3)
	port := newPort()

	rep, err := vendRun(f, port, func(o *engine.Options) { o.DryRun = true })
	require.NoErrorf(t, err, "preview: %v", err)
	assert.Equalf(t, 3, rep.Shipped, "preview reported %d would-ship files of 3", rep.Shipped)
	assert.Equal(t, 0, len(port.sizes()))
	assert.Equalf(t, 0, f.store.Len(), "preview committed %d fingerprints", f.store.Len())
}

// Derived objects take the upload path too, after every raw unit of the source has shipped.
func TestDerivedObjectsShipThroughTheUploadPath(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)
	port := newPort()

	o := enrichOpts(t, f, db, true)
	o.Upload = port
	rep, err := engine.Run(context.Background(), f.store, o)
	require.NoErrorf(t, err, "run: %v", err)

	require.Equalf(t, 2, rep.Shipped, "expected a raw + derived pair, shipped %d: %+v", rep.Shipped, rep.Sources)
	port.storedOnce(t)

	port.mu.Lock()
	defer port.mu.Unlock()
	assert.Lenf(t, port.objects, 2, "%d distinct keys authorized for a raw + derived pair", len(port.objects))
	assert.Lenf(t, port.groups, 2, "groups %v; the raw pass and the enricher each authorize their own", port.groups)
}

// An unauthorized enricher group reports once and commits nothing, while raw objects keep their
// commits. The halt must come back out of engine.Run, or the run would exit zero and look healthy.
func TestAnUnavailableControlPlaneStopsTheDerivedGroup(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)
	port := newPort()
	// The raw pass ships; only the enricher's group is refused.
	port.verdict = func(call, _ int, _ engine.PreparedObject) error {
		if call == 0 {
			return nil
		}
		return fmt.Errorf("backend: HTTP 503: %w", engine.ErrUploadUnavailable)
	}

	o := enrichOpts(t, f, db, true)
	o.Upload = port
	rep, err := engine.Run(context.Background(), f.store, o)
	require.ErrorIsf(t, err, engine.ErrUploadUnavailable, "the derived halt did not reach the caller: %v", err)
	assert.True(t, !errors.Is(err, formats.ErrCredentialsRefused), "an unavailable control plane killed the install from the derived path")
	assert.Equalf(t, 1, rep.Shipped, "shipped %d; the raw object ships and the derived one does not", rep.Shipped)
	derived := 0
	for _, fo := range rep.Sources[0].Files {
		if !fo.Derived {
			continue
		}
		derived++
		assert.Equalf(t, formats.DecisionFailed, fo.Decision, "the derived object decided %q while authorization was unavailable", fo.Decision)
	}
	assert.Equalf(t, 1, derived, "%d derived outcomes reported, want 1", derived)
}

// The halt latch belongs to the source, not to one enricher: a second enricher must not ship
// under credentials the control plane has just rejected.
func TestARefusedDerivedGroupStopsTheRemainingEnrichers(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)
	port := newPort()
	// Call 0 is the raw pass; the enricher's group is what gets refused.
	port.verdict = func(call, _ int, _ engine.PreparedObject) error {
		if call == 0 {
			return nil
		}
		return fmt.Errorf("backend: refused: %w", formats.ErrCredentialsRefused)
	}

	// Sorted after cursor-transcript-join, because enrichers run in id order.
	second := &countingEnricher{id: "zz-never-runs"}
	o := enrichOpts(t, f, db, true)
	o.Upload = port
	o.Enrichers = transforms.NewRegistry(&fixtureEnricher{Enricher: cursorjoin.New(), db: db}, second)
	o.Plan.Sources[0].Enrichers[second.id] = true

	if _, err := engine.Run(context.Background(), f.store, o); !errors.Is(err, formats.ErrCredentialsRefused) {
		t.Fatalf("a refused derived group did not stop the run: %v", err)
	}
	assert.Equalf(t, 0, second.calls, "the second enricher ran %d time(s) after the first was refused", second.calls)
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
