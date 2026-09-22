package engine_test

import (
	"os"
	"path/filepath"
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

	f.appendTranscript("p/s1.jsonl", line2)
	rep := f.run()

	require.Equalf(t, 1, rep.Shipped, "the grown file should re-ship: %+v", rep)
	if got := f.port.keys(); len(got) != 1 || got[0] != keysAfterFirst[0] {
		t.Errorf("keys changed: %v, want %v", got, keysAfterFirst)
	}
	obj, _, payload := f.openObject(t, keysAfterFirst[0])
	assert.Equalf(t, 2, obj.Versions, "expected version 2, got %d — history is noncurrent versions", obj.Versions)

	// Both lines must be present: the whole file ships, not a delta.

	assert.Truef(t, strings.Contains(string(payload), `"uuid":"u1"`) && strings.Contains(string(payload), `"uuid":"a1"`), "the re-shipped object is not the whole file: %s", payload)
}

// Touching mtime without changing bytes must re-ship nothing: the content hash is the authority.
func TestMTimeTouchDoesNotReship(t *testing.T) {
	f := newFixture(t)
	paths := []string{"p/a.jsonl", "p/b.jsonl", "p/c.jsonl"}
	for _, p := range paths {
		f.writeTranscript(p, line1)
	}

	first := f.run()
	require.Equalf(t, 3, first.Shipped, "expected 3 shipped, got %+v", first)
	f.port.reset()

	// Rewrite identical content with a new mtime, as the MCP descriptors do on a live Cursor store.
	later := time.Now().Add(time.Hour)
	for _, p := range paths {
		full := filepath.Join(f.home, ".claude", "projects", p)
		require.NoError(t, os.WriteFile(full, []byte(line1), 0o600))
		require.NoError(t, os.Chtimes(full, later, later))
	}

	second := f.run()
	assert.Equalf(t, 0, second.Shipped, "nothing should re-ship on an mtime-only change, got %d", second.Shipped)
	assert.Equalf(t, 3, second.Unchanged, "expected 3 unchanged, got %+v", second)
	assert.Equal(t, 0, f.port.putCount())
}

// The pre-filter must NOT read a file whose stat has not moved: "size and mtime unchanged" means
// never opened. The mtime carries nanoseconds: a whole-second fixture cannot see the precision bug.
func TestAnUnchangedFileIsNotReadTwice(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)

	full := filepath.Join(f.home, ".claude", "projects", "p/a.jsonl")
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second).Add(123456789 * time.Nanosecond)
	require.NoError(t, os.Chtimes(full, stamp, stamp))
	if got := statMTime(t, full); got.Nanosecond() == 0 {
		t.Skipf("this filesystem stores whole-second mtimes (%s); the pre-filter cannot be "+
			"distinguished from the hash path here", got)
	}

	require.Equal(t, 1, f.run().Shipped)

	// Reopened, because that is what the next tick is: in one process the bug is invisible.
	f.reopen()

	second := f.run()
	require.Equalf(t, 1, second.Unchanged, "expected 1 unchanged, got %+v", second)

	// Read off the run's own outcome: per-file unchanged entries are elided from the audit log.
	var reason string
	for _, s := range second.Sources {
		for _, fo := range s.Files {
			if fo.Decision == auditlog.DecisionUnchanged {
				reason = fo.Reason
			}
		}
	}
	assert.Equal(t, "size and mtime unchanged", reason)
}

// Per-file unchanged entries would grow the log at scan rate, so one aggregate replaces them.
func TestUnchangedFilesAuditAsOneAggregateEntry(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line2)
	f.writeTranscript("p/c.jsonl", line1)

	require.Equal(t, 3, f.run().Shipped)
	f.reopen()
	require.Equal(t, 3, f.run().Unchanged)

	entries, err := auditlog.Tail(f.log.Path(), 0)
	require.NoError(t, err)
	perFile, aggregates := 0, 0
	var reason string
	for _, e := range entries {
		if e.Decision != auditlog.DecisionUnchanged {
			continue
		}
		if e.File != "" {
			perFile++
		} else {
			aggregates++
			reason = e.Reason
		}
	}
	assert.Equalf(t, 0, perFile, "%d per-file unchanged entries; the elision is not happening", perFile)
	require.Equalf(t, 1, aggregates, "%d aggregate unchanged entries, want exactly 1", aggregates)
	assert.Equal(t, reason, "3 files unchanged by size and mtime, not opened; per-file entries elided")
}

// Only files the run never opened are elided; one it READ keeps its per-file entry.
func TestAReadButUnchangedFileKeepsItsPerFileAuditEntry(t *testing.T) {
	f := newFixture(t)
	path := f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line2)

	require.Equal(t, 2, f.run().Shipped)

	// A new mtime under identical bytes: the pre-filter cannot clear it, so the run reads it.
	later := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(path, later, later))
	f.reopen()
	require.Equal(t, 2, f.run().Unchanged)

	entries, err := auditlog.Tail(f.log.Path(), 0)
	require.NoError(t, err)
	perFile, aggregates := 0, 0
	for _, e := range entries {
		if e.Decision != auditlog.DecisionUnchanged {
			continue
		}
		if e.File == "" {
			aggregates++
			continue
		}
		perFile++
		assert.Equalf(t, path, e.File, "per-file unchanged entry for %s, want %s", e.File, path)
		assert.NotEqual(t, int64(0), e.BytesIn, "the per-file entry must carry the bytes the run read")
	}
	assert.Equalf(t, 1, perFile, "%d per-file unchanged entries, want exactly 1: the file the run read", perFile)
	assert.Equalf(t, 1, aggregates, "%d aggregate entries, want 1: the file the pre-filter passed over", aggregates)
}

// A spec change resets exactly that source's state, so the file re-ships onto its existing key.
func TestSpecChangeResetsOnlyThatSource(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.run()
	keyBefore := f.port.keys()[0]

	f.eff.Sources[0].SpecFingerprint = strings.Repeat("b", 64)
	rep := f.run()

	assert.Equalf(t, 1, rep.Shipped, "a spec change should re-ship the source: %+v", rep)
	if got := f.port.keys(); len(got) != 1 || got[0] != keyBefore {
		t.Errorf("the key must not change with the spec: %v", got)
	}
}

// After a spec change preview must report the same would-ship as a real sync, persisting nothing.
func TestPreviewReportsWouldShipAfterSpecChange(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.run()
	uploadsBefore := len(f.port.keys())

	f.eff.Sources[0].SpecFingerprint = strings.Repeat("b", 64)
	rep := f.runDry()

	assert.Equalf(t, 1, rep.Shipped, "preview after a spec change should report would-ship, not unchanged: %+v", rep)
	assert.Len(t, f.port.keys(), uploadsBefore, "preview uploaded something")
	assert.Equalf(t, 1, f.store.Len(), "preview must not drop entries: %d left", f.store.Len())

	// A real run afterwards still re-ships, so preview changed nothing about the next sync.
	assert.Equal(t, 1, f.run().Shipped)
}
