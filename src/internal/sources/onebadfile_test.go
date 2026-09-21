package sources_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// One unreadable file must not silence the whole source: the sniff asks about the STORE, so it samples more than one file.
func TestOneUnreadableFileDoesNotSilenceTheSource(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "projects", "p")
	require.NoError(t, os.MkdirAll(dir, 0o700))

	// The oldest file is the broken one.
	bad := filepath.Join(dir, "00000000-0000-4000-8000-000000000000.jsonl")
	require.NoError(t, os.WriteFile(bad, []byte("\x00\x00\x00 not json at all\n"), 0o600))
	older(t, bad)

	for _, name := range []string{"11111111", "22222222", "33333333"} {
		good := filepath.Join(dir, name+"-1111-4111-8111-111111111111.jsonl")
		require.NoError(t, os.WriteFile(good, []byte(`{"type":"user","uuid":"u1"}`+"\n"), 0o600))
	}

	d := discover(t, source(filepath.Join(home, ".claude"), []string{"projects/**/*.jsonl"}), nil)

	assert.Equalf(t, sources.Collected, d.Health, "health %q (%s) — one bad file is not a broken source", d.Health, d.Reason)
	assert.Lenf(t, d.Candidates, 4, "got %d candidates, want all 4: the bad one fails per-file, not source-wide", len(d.Candidates))
	assert.NotEqual(t, 0, d.SniffFailures, "the bad file was not noticed at all; it should be counted even when the source is fine")
}

// The source-wide verdict must still exist: a store that really did change substrate has to stop collection.
func TestASourceWhereEveryFileIsUnreadableIsStillCondemned(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "projects", "p")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	for _, name := range []string{"11111111", "22222222", "33333333"} {
		p := filepath.Join(dir, name+"-1111-4111-8111-111111111111.jsonl")
		require.NoError(t, os.WriteFile(p, []byte("\x00\x00\x00 encrypted now\n"), 0o600))
	}

	d := discover(t, source(filepath.Join(home, ".claude"), []string{"projects/**/*.jsonl"}), nil)

	assert.NotEqual(t, sources.Collected, d.Health, "every file is unreadable and the source reports collected")
	assert.Lenf(t, d.Candidates, 0, "%d candidates from a store that cannot be read", len(d.Candidates))
}

func older(t *testing.T, path string) {
	t.Helper()
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(path, old, old))
}
