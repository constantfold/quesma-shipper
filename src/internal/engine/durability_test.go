package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// State loss re-uploads onto the same keys, adding a version to each existing object.
func TestStateLossReusesObjectKeys(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/s%d.jsonl", 3)
	f.run()
	before := f.port.keys()
	require.Len(t, before, 3)

	f.store.Close()
	require.NoError(t, os.Remove(filepath.Join(f.stateDir, engine.FileName)))
	f.reopen()
	require.Equal(t, 3, f.run().Shipped)
	assert.Equal(t, before, f.port.keys())
	for _, key := range before {
		obj, _, _ := f.openObject(t, key)
		assert.Equal(t, 2, obj.Versions, "re-upload must add a version")
	}
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

// Batching is measured as document replacements, which a fast disk would hide in a timing.
func TestARunReplacesTheStateDocumentOncePerBatchNotOncePerFile(t *testing.T) {
	f := newFixture(t)
	const files = 25
	f.writeTranscripts("p/a%02d.jsonl", files)

	writes := f.countStateWrites(func() {
		require.Equal(t, files, f.run(func(o *engine.Options) { o.CommitBatch = 10 }).Shipped)
	})

	// 25 files at a batch of 10: two batches, the source-boundary flush, plus project-map's own.
	assert.Truef(t, writes <= 6, "state document replaced %d times for %d files; batching is not working", writes, files)
	assert.NotEqual(t, 0, writes, "the state document was never written; nothing was made durable")

	// The five past the last full batch must be durable when the run returns, too.
	f.reopen()
	rep := f.run()
	assert.Truef(t, rep.Shipped == 0 && rep.Unchanged == files, "after a reload the run should ship nothing and see %d unchanged, got %+v", files, rep)
}

// The flag must survive Run replacing the whole report struct, which once dropped it.
func TestARunReportsThatItDiscardedTheStore(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	require.False(t, f.run().StoreCorrupt, "a healthy store reported as corrupt")

	// A flipped hex digit: still valid JSON, still schema-clean, only the checksum catches it.
	path := filepath.Join(f.stateDir, engine.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	tampered := strings.Replace(string(raw), `"source_hash": "`, `"source_hash": "f`, 1)
	require.NoError(t, os.WriteFile(path, []byte(tampered[:len(tampered)-1]), 0o600))

	f.reopen()
	assert.True(t, f.run().StoreCorrupt, "the run did not report discarding the store")
}
