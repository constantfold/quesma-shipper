package engine_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

const installID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const otherSha = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"

const otherInstall = "85a7e04c-32a4-4bf5-9c80-49c4f9d087bb"

// What a re-enrolled machine wakes up to: a document another install left behind.
func seedForeignDoc(t *testing.T, dir string, entries int) {
	t.Helper()
	s, err := engine.Open(dir, otherInstall)
	require.NoError(t, err)
	defer s.Close()
	_, ensureSpecErr := s.EnsureSpec("claude-code-transcripts", strings.Repeat("a", 64))
	require.NoError(t, ensureSpecErr)
	for i := 0; i < entries; i++ {
		require.NoError(t, commit(s, key(fmt.Sprintf("/x/%d.jsonl", i)), fingerprint()))
	}
}

func key(path string) engine.Key {
	return engine.Key{SourceID: "claude-code-transcripts", NativePath: path}
}

// fixedMTime keeps the fixture deterministic. The nanoseconds are not decoration: a whole-second
// mtime cannot catch a serializer that truncates, and no real filesystem hands out whole seconds.
var fixedMTime = time.Date(2026, 7, 30, 10, 0, 0, 987654321, time.UTC)

func fingerprint() engine.Fingerprint {
	return engine.Fingerprint{SourceSize: 4096, SourceMTime: fixedMTime, SourceHash: sha}
}

// commit is the one-entry CommitAll these tests are written against.
func commit(s *engine.Store, k engine.Key, fp engine.Fingerprint) error {
	return s.CommitAll(map[engine.Key]engine.Fingerprint{k: fp})
}

func open(t *testing.T, dir string) *engine.Store {
	t.Helper()
	s, err := engine.Open(dir, installID)
	require.NoErrorf(t, err, "open: %v", err)
	t.Cleanup(func() { s.Close() })
	return s
}

// A store locks writers, exposes durable reads, and preserves exact fingerprints across reopen.
func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, engine.FileName)
	s := open(t, dir)
	assert.Zero(t, s.Len())
	assert.False(t, s.Corrupt(), "a missing document is a first run")
	_, known := s.Get(key("/x/a.jsonl"))
	assert.False(t, known)
	_, err := engine.Open(dir, installID)
	require.ErrorIs(t, err, engine.ErrLocked, "a concurrent writer must be refused")

	// A previous process with this PID may have died before replacing the document.
	require.NoError(t, os.WriteFile(path+fmt.Sprintf(".tmp-%d", os.Getpid()), []byte(`{"half":"written`), 0o600))
	// A derived entry's enricher and output hash round-trip too.
	want := fingerprint()
	want.Enricher, want.OutputHash = &engine.EnricherRef{ID: "cursor-transcript-join", Version: 1}, otherSha
	require.NotZero(t, want.SourceMTime.Nanosecond(), "whole seconds would hide lost timestamp precision")
	require.NoError(t, commit(s, key("/x/a.jsonl"), want))

	doc, err := engine.Peek(dir)
	require.NoError(t, err, "Peek must work while the writer holds the lock")
	assert.Equal(t, installID, doc.InstallID)
	assert.Equal(t, map[engine.Key]engine.Fingerprint{key("/x/a.jsonl"): want}, doc.Entries)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s = open(t, dir)
	got, known := s.Get(key("/x/a.jsonl"))
	require.True(t, known, "the entry must survive reopen")
	assert.Equal(t, want, got)
	require.NoError(t, s.Close())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "open, read and close must not rewrite committed state")

	require.NoError(t, os.Remove(path))
	s = open(t, dir)
	assert.Zero(t, s.Len(), "losing the document forgets progress")
	assert.False(t, s.Corrupt(), "a removed document is a fresh start")
}

// The document is deterministic, so a diff shows real change rather than map ordering.
func TestDocumentIsDeterministic(t *testing.T) {
	write := func(dir string, paths []string) string {
		s, err := engine.Open(dir, installID)
		require.NoError(t, err)
		defer s.Close()
		for _, p := range paths {
			require.NoError(t, commit(s, key(p), fingerprint()))
		}
		raw, err := os.ReadFile(filepath.Join(dir, engine.FileName))
		require.NoError(t, err)
		// updated_at moves per flush, and checksum covers it; strip both so the comparison is
		// about ordering.
		var out []string
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "updated_at") && !strings.Contains(line, "checksum") {
				out = append(out, line)
			}
		}
		return strings.Join(out, "\n")
	}

	forward := write(t.TempDir(), []string{"/x/a.jsonl", "/x/b.jsonl", "/x/c.jsonl"})
	reverse := write(t.TempDir(), []string{"/x/c.jsonl", "/x/b.jsonl", "/x/a.jsonl"})
	assert.Equalf(t, reverse, forward, "insertion order changed the document:\n%s\n---\n%s", forward, reverse)
}

// A spec change means the source is read differently, so only its entries drop.
func TestEnsureSpecDropsOnlyTheChangedSource(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)

	for _, id := range []string{"claude-code-transcripts", "codex-rollouts"} {
		_, ensureSpecErr := s.EnsureSpec(id, sha)
		require.NoError(t, ensureSpecErr)
	}
	entries := []engine.Key{
		{SourceID: "claude-code-transcripts", NativePath: "/x/a.jsonl"},
		{SourceID: "claude-code-transcripts", NativePath: "/x/b.jsonl"},
		{SourceID: "codex-rollouts", NativePath: "/y/r.jsonl"},
	}
	for _, k := range entries {
		require.NoError(t, commit(s, k, fingerprint()))
	}

	if n, err := s.EnsureSpec("claude-code-transcripts", sha); err != nil || n != 0 {
		t.Fatalf("an unchanged spec must drop nothing: n=%d err=%v", n, err)
	}
	if n, err := s.EnsureSpec("claude-code-transcripts", otherSha); err != nil || n != 2 {
		t.Fatalf("a changed spec must drop that source's entries: n=%d err=%v", n, err)
	}
	assert.Equalf(t, 1, s.Len(), "expected 1 surviving entry, got %d", s.Len())
	if _, ok := s.Get(entries[2]); !ok {
		t.Error("an unrelated source must not be touched")
	}
}
