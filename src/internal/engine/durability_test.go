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

// A crash between the upload and the commit re-runs the file onto the same key. Zero new keys.
func TestCrashBeforeCommitReRunsOntoTheSameKey(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	// The lost commit is simulated by wiping state after a successful upload.
	f.run()
	keys := f.port.keys()
	require.Lenf(t, keys, 1, "expected 1 key, got %v", keys)

	f.wipeState()
	f.port.reset()

	rep := f.run()
	require.Equalf(t, 1, rep.Shipped, "the file should be re-run: %+v", rep)
	if got := f.port.keys(); len(got) != 1 || got[0] != keys[0] {
		t.Errorf("re-run created a new key: %v, want %v", got, keys)
	}
	obj, _ := f.port.get(keys[0])
	assert.Equalf(t, 2, obj.Versions, "expected the re-run to add a version, got %d", obj.Versions)
}

// Wiping the fingerprint document while keeping the identity converges: ZERO new keys.
func TestWipedStateConvergesWithZeroNewKeys(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"p/a.jsonl", "p/b.jsonl", "p/c.jsonl"} {
		f.writeTranscript(p, line1)
	}

	f.run()
	before := f.port.keys()
	require.Lenf(t, before, 3, "expected 3 keys, got %v", before)

	f.wipeState()

	rep := f.run()
	assert.Equalf(t, 3, rep.Shipped, "everything should re-upload once: %+v", rep)
	after := f.port.keys()
	require.Lenf(t, after, len(before), "the bucket gained keys: %v, want %v", after, before)
	for i := range before {
		assert.Equalf(t, after[i], before[i], "key %d changed: %s -> %s", i, before[i], after[i])
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

	after := snapshot(t, agentDir)
	assert.Len(t, before, len(after))
	for path, hash := range before {
		got, ok := after[path]
		if !ok {
			t.Errorf("%s disappeared", path)
			continue
		}
		assert.Equalf(t, hash, got, "%s was modified", path)
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("%s was created inside the agent store", path)
		}
	}
}

// What batching must show is how often the state document is replaced. The count is asserted
// rather than the timing, which a fast disk would hide.
func TestARunReplacesTheStateDocumentOncePerBatchNotOncePerFile(t *testing.T) {
	f := newFixture(t)
	const files = 25
	for i := 0; i < files; i++ {
		f.writeTranscript(fmt.Sprintf("p/a%02d.jsonl", i), line1)
	}

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
	for i := 0; i < files; i++ {
		f.writeTranscript(fmt.Sprintf("p/b%02d.jsonl", i), line1)
	}
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
