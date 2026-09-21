package engine_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Reset is the one-command full re-ship onto existing keys; its dry run must not write.
func TestResetForgetsEverythingButOnlyWithApply(t *testing.T) {
	dir := t.TempDir()

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	require.NoError(t, commit(s, key("/x/b.jsonl"), fingerprint()))
	s.Close()

	removed, err := engine.Reset(dir, installID, true)
	require.NoError(t, err)
	assert.Equalf(t, 2, removed, "dry run should count both entries, counted %d", removed)
	s2 := open(t, dir)
	require.Equalf(t, 2, s2.Len(), "a dry run wrote: %d entries remain, want 2", s2.Len())
	s2.Close()

	removed, err = engine.Reset(dir, installID, false)
	require.NoError(t, err)
	assert.Equalf(t, 2, removed, "apply should count what it forgot, counted %d", removed)
	s3 := open(t, dir)
	defer s3.Close()
	assert.Equalf(t, 0, s3.Len(), "apply left %d entries", s3.Len())
}

// A reset store keeps its install id, so a later open under another identity still discards it.
func TestResetKeepsTheInstallID(t *testing.T) {
	dir := t.TempDir()

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()

	if _, err := engine.Reset(dir, installID, false); err != nil {
		t.Fatal(err)
	}
	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Equalf(t, installID, doc.InstallID, "a reset document lost its install id: %q", doc.InstallID)
}

// Resetting an empty store is a no-op, not an error: it must be safe to run fleet-wide.
func TestResetOnAnEmptyStoreIsANoOp(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.Close()

	removed, err := engine.Reset(dir, installID, false)
	require.NoError(t, err)
	assert.Equalf(t, 0, removed, "an empty store forgot %d entries", removed)
}

// An unloadable document is what an operator runs reset against, so --apply must replace it even
// though the discarded store forgot nothing.
func TestResetReplacesAnUnloadableDocument(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte("not a document\n"), 0o600))
	if _, err := engine.Reset(dir, installID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Peek(dir); err != nil {
		t.Fatalf("the document was not replaced: %v", err)
	}
}

// Re-enrolling replaces identity.json and leaves the old install's document behind. Its entries
// name objects under that install's key root, so not one of them may survive into this install.
func TestAnotherInstallsEntriesNeverSurvive(t *testing.T) {
	dir := t.TempDir()
	seedForeignDoc(t, dir, 3)

	s, err := engine.Open(dir, installID)
	require.NoErrorf(t, err, "a foreign document must be discarded, not refused: %v", err)
	assert.True(t, s.Corrupt(), "the discard was not reported to the run")
	require.Equalf(t, 0, s.Len(), "%d of another install's entries survived", s.Len())
	require.NoError(t, commit(s, key("/x/mine.jsonl"), fingerprint()))
	s.Close()

	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Equalf(t, installID, doc.InstallID, "the replacement kept the foreign install id %q", doc.InstallID)
	assert.True(t, !doc.ForeignTo(installID), "the replacement still reads as foreign, so the next run discards it again")
	assert.Lenf(t, doc.Entries, 1, "the replacement holds %d entries, want only this install's one", len(doc.Entries))
}

// Prune keeps entries, so it is the verb that could claim another install's uploads. It cannot:
// the discard empties the store before pruning ever looks at it.
func TestPruneCannotClaimAnotherInstallsUploads(t *testing.T) {
	dir := t.TempDir()
	seedForeignDoc(t, dir, 2)

	removed, kept, err := engine.Prune(dir, installID, false)
	require.NoErrorf(t, err, "prune over a foreign document: %v", err)
	assert.Truef(t, removed == 0 && kept == 0, "prune reported removed=%d kept=%d over a discarded store, want 0 and 0", removed, kept)
	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Truef(t, len(doc.Entries) == 0 && doc.InstallID == installID, "prune left %d entries under install %q", len(doc.Entries), doc.InstallID)
}

// An entryless foreign document forgets nothing, so only the install id makes it a replacement.
// Reset must still write it, or the stale id survives and every run re-discards the file.
func TestResetReplacesAnEmptyForeignDocument(t *testing.T) {
	dir := t.TempDir()
	seedForeignDoc(t, dir, 0)

	removed, err := engine.Reset(dir, installID, false)
	require.NoError(t, err)
	assert.Equalf(t, 0, removed, "an entryless document forgot %d entries", removed)
	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Equalf(t, installID, doc.InstallID, "reset left the foreign install id %q in place", doc.InstallID)
}

// A dry run reports; it never writes. The in-memory discard must not reach the file.
func TestADryRunLeavesAnUnloadableDocumentOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, engine.FileName)
	original := []byte("not a document\n")
	require.NoError(t, os.WriteFile(path, original, 0o600))

	for _, run := range []struct {
		name string
		fn   func() error
	}{
		{"reset", func() error { _, err := engine.Reset(dir, installID, true); return err }},
		{"prune", func() error { _, _, err := engine.Prune(dir, installID, true); return err }},
	} {
		require.NoError(t, run.fn())
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, string(got), string(original))
	}
}

// Reset contends like every verb: told the store is busy, never queued behind it.
func TestResetIsRefusedWhileLocked(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	defer s.Close()

	if _, err := engine.Reset(dir, installID, false); !errors.Is(err, engine.ErrLocked) {
		t.Errorf("reset under a held lock: err = %v, want ErrLocked", err)
	}
}
