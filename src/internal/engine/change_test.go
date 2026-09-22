package engine_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// Appending two lines re-ships the file whole onto the SAME key, adding a version.
func TestAppendTwoLinesOverwritesTheSameKey(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	f.run()
	keysAfterFirst := f.port.keys()
	require.Lenf(t, keysAfterFirst, 1, "expected 1 key, got %v", keysAfterFirst)

	f.writeTranscript("p/s1.jsonl", line1+line2)
	rep := f.run()

	require.Equalf(t, 1, rep.Shipped, "the grown file should re-ship: %+v", rep)
	assert.Equal(t, keysAfterFirst, f.port.keys(), "the key changed")
	obj, _, payload := f.openObject(t, keysAfterFirst[0])
	assert.Equalf(t, 2, obj.Versions, "expected version 2, got %d — history is noncurrent versions", obj.Versions)

	// Both lines must be present: the whole file ships, not a delta.
	assert.Truef(t, strings.Contains(string(payload), `"uuid":"u1"`) && strings.Contains(string(payload), `"uuid":"a1"`), "the re-shipped object is not the whole file: %s", payload)
}

// Stat-only skips coalesce; a hash-verified read keeps its entry. The reopen is the next tick.
func TestUnchangedFileAudit(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(fmt.Sprintf("read=%t", read), func(t *testing.T) {
			f := newFixture(t)
			path := f.writeTranscript("p/a.jsonl", line1)
			f.writeTranscript("p/b.jsonl", line2)
			count := 2
			if !read {
				f.writeTranscript("p/c.jsonl", line1)
				count++
			}
			require.Equal(t, count, f.run().Shipped)
			if read {
				// A new mtime under identical bytes forces the content-hash check.
				later := time.Now().Add(time.Hour)
				require.NoError(t, os.Chtimes(path, later, later))
			}
			f.reopen()
			require.Equal(t, count, f.run().Unchanged)

			entries, err := auditlog.Tail(f.log.Path(), 0)
			require.NoError(t, err)
			var perFile, aggregate []auditlog.Entry
			for _, e := range entries {
				if e.Decision != auditlog.DecisionUnchanged {
					continue
				}
				if e.File == "" {
					aggregate = append(aggregate, e)
				} else {
					perFile = append(perFile, e)
				}
			}
			require.Len(t, aggregate, 1, "stat-only skips must coalesce")
			if read {
				require.Len(t, perFile, 1)
				assert.Equal(t, path, perFile[0].File)
				assert.NotZero(t, perFile[0].BytesIn)
			} else {
				assert.Empty(t, perFile)
				assert.Equal(t, "3 files unchanged by size and mtime, not opened; per-file entries elided", aggregate[0].Reason)
			}
		})
	}
}

// After a spec change preview must report the same would-ship as a real sync, persisting nothing.
func TestSpecChangeLifecycle(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.run()
	keysBefore := f.port.keys()
	require.Len(t, keysBefore, 1)

	f.plan.Sources[0].SpecFingerprint = strings.Repeat("b", 64)
	rep := f.run(dryRun)

	assert.Equalf(t, 1, rep.Shipped, "preview after a spec change should report would-ship, not unchanged: %+v", rep)
	assert.Equal(t, keysBefore, f.port.keys(), "preview uploaded something")
	assert.Equalf(t, 1, f.store.Len(), "preview must not drop entries: %d left", f.store.Len())

	// A real run afterwards still re-ships, so preview changed nothing about the next sync.
	assert.Equal(t, 1, f.run().Shipped)
	assert.Equal(t, keysBefore, f.port.keys(), "the key must not change with the spec")
}
