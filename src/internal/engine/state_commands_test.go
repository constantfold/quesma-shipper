package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Reset respects the writer lock and dry-run mode, and preserves identity when clearing progress.
func TestResetLifecycle(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	_, err := engine.Reset(dir, installID, false)
	require.ErrorIs(t, err, engine.ErrLocked)
	require.NoError(t, s.Close())
	removed, err := engine.Reset(dir, installID, false)
	require.NoError(t, err)
	assert.Zero(t, removed, "an empty store has nothing to forget")

	s = open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	require.NoError(t, commit(s, key("/x/b.jsonl"), fingerprint()))
	require.NoError(t, s.Close())
	before, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)

	removed, err = engine.Reset(dir, installID, true)
	require.NoError(t, err)
	assert.Equal(t, 2, removed)
	s = open(t, dir)
	require.Equal(t, 2, s.Len(), "a dry run must retain both entries")
	require.NoError(t, s.Close())
	after, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.Equal(t, before, after, "a dry run must not rewrite the document")

	removed, err = engine.Reset(dir, installID, false)
	require.NoError(t, err)
	assert.Equal(t, 2, removed)
	assert.Zero(t, open(t, dir).Len())
	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Equal(t, installID, doc.InstallID)
}

// Reset and prune replace an unloadable or foreign document on --apply, even when the discarded
// store forgot nothing, or the stale document is re-discarded every run. A dry run never writes.
// Prune keeps entries, yet cannot claim another install's uploads: the discard empties it first.
func TestOverridesReplaceADiscardedDocument(t *testing.T) {
	garbage := func(t *testing.T, dir string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte("not a document\n"), 0o600))
	}
	reset := func(dir string, dry bool) (int, error) { return engine.Reset(dir, installID, dry) }
	prune := func(dir string, dry bool) (int, error) {
		removed, kept, err := engine.Prune(dir, installID, dry)
		return removed + kept, err
	}
	for _, tc := range []struct {
		name string
		seed func(*testing.T, string)
		cmd  func(string, bool) (int, error)
		dry  bool
	}{
		{"reset unloadable", garbage, reset, false},
		{"reset unloadable dry", garbage, reset, true},
		{"prune unloadable dry", garbage, prune, true},
		{"reset empty foreign", func(t *testing.T, dir string) { seedForeignDoc(t, dir, 0) }, reset, false},
		{"prune foreign", func(t *testing.T, dir string) { seedForeignDoc(t, dir, 2) }, prune, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.seed(t, dir)
			path := filepath.Join(dir, engine.FileName)
			before, err := os.ReadFile(path)
			require.NoError(t, err)

			n, err := tc.cmd(dir, tc.dry)
			require.NoError(t, err)
			assert.Zero(t, n, "a discarded store has nothing to remove or keep")
			if tc.dry {
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, string(before), string(after))
				return
			}
			doc, err := engine.Peek(dir)
			require.NoError(t, err, "the document was not replaced")
			assert.Equal(t, installID, doc.InstallID)
			assert.Empty(t, doc.Entries)
		})
	}
}
