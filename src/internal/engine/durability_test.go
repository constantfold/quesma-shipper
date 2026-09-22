package engine_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// State loss re-uploads onto the same keys, preserving the store's existing versions.
func TestStateLossReusesObjectKeys(t *testing.T) {
	for _, paths := range [][]string{{"p/s1.jsonl"}, {"p/a.jsonl", "p/b.jsonl", "p/c.jsonl"}} {
		t.Run(fmt.Sprintf("files=%d", len(paths)), func(t *testing.T) {
			f := newFixture(t)
			for _, path := range paths {
				f.writeTranscript(path, line1)
			}
			f.run()
			before := f.port.keys()
			require.Len(t, before, len(paths))
			f.wipeState()
			if len(paths) == 1 {
				f.port.reset()
			}
			rep := f.run()
			require.Equal(t, len(paths), rep.Shipped)
			require.Len(t, f.port.keys(), len(before))
			assert.Equal(t, before, f.port.keys())
			for _, key := range before {
				obj, _, _ := f.openObject(t, key)
				assert.Equal(t, 2, obj.Versions, "re-upload must add a version")
			}
		})
	}
}

// A failed upload commits nothing, so the next tick re-runs the file.
func TestFailedUploadCommitsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	f.port.FailNext = errors.New("network is unreachable")
	rep := f.run()
	require.Equalf(t, 1, rep.Failed, "expected a failure, got %+v", rep)
	assert.Len(t, f.port.keys(), 0, "nothing should have landed")

	rep2 := f.run()
	assert.Equalf(t, 1, rep2.Shipped, "the next tick must re-run the file: %+v", rep2)
}

// A full cycle must not write anything under the agent's directory: no sidecars, no temp files.
func TestNeverMutatesTheAgentStore(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line1+line2)

	agentDir := filepath.Join(f.home, ".claude")
	before := snapshot(t, agentDir)

	f.run()
	f.run() // twice, so an idempotent second pass is covered too

	assert.Equal(t, before, snapshot(t, agentDir), "a sync must neither create, remove nor modify agent files")
}

// What batching must show is how often the state document is replaced. The count is asserted
// rather than the timing, which a fast disk would hide.
func TestARunReplacesTheStateDocumentOncePerBatchNotOncePerFile(t *testing.T) {
	f := newFixture(t)
	const files = 25
	f.writeTranscripts("p/a%02d.jsonl", files)

	writes := f.countStateWrites(func() {
		require.Equal(t, files, f.runWith(func(o *engine.Options) { o.CommitBatch = 10 }).Shipped)
	})

	// 25 files at a batch of 10: two batches, the source-boundary flush, plus project-map's own.
	assert.Truef(t, writes <= 6, "state document replaced %d times for %d files; batching is not working", writes, files)
	assert.NotEqual(t, 0, writes, "the state document was never written; nothing was made durable")
}

// Everything a run shipped must be durable when the run returns, whatever exit it takes.
func TestEverythingShippedIsDurableWhenTheRunReturns(t *testing.T) {
	f := newFixture(t)
	const files = 12
	f.writeTranscripts("p/b%02d.jsonl", files)
	require.Equal(t, files, f.runWith(func(o *engine.Options) { o.CommitBatch = 1000 }).Shipped)

	f.reopen()
	if rep := f.run(); rep.Shipped != 0 || rep.Unchanged != files {
		t.Errorf("after a reload the run should ship nothing and see %d unchanged, got %+v",
			files, rep)
	}
}

// The flag has to survive Run's own report construction: it was first set before the line that
// replaces the whole struct, so the discard was detected and then silently dropped on the floor.
func TestARunReportsThatItDiscardedTheStore(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	if rep := f.run(); rep.StoreCorrupt {
		t.Fatalf("a healthy store reported as corrupt: %+v", rep)
	}

	// A flipped hex digit: still valid JSON, still schema-clean, only the checksum catches it.
	path := filepath.Join(f.stateDir, engine.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	tampered := strings.Replace(string(raw), `"source_hash": "`, `"source_hash": "f`, 1)
	require.NoError(t, os.WriteFile(path, []byte(tampered[:len(tampered)-1]), 0o600))

	f.reopen()
	if rep := f.run(); !rep.StoreCorrupt {
		t.Errorf("the run did not report discarding the store: %+v", rep)
	}
}
