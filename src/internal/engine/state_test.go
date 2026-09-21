package engine_test

import (
	"errors"
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
	if _, err := s.EnsureSpec("claude-code-transcripts", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < entries; i++ {
		require.NoError(t, commit(s, key(fmt.Sprintf("/x/%d.jsonl", i)), fingerprint()))
	}
}

func key(path string) engine.Key {
	return engine.Key{
		SourceID:   "claude-code-transcripts",
		NativePath: path,
	}
}

// fixedMTime keeps the fixture deterministic. The nanoseconds are not decoration: a whole-second
// mtime cannot catch a serializer that truncates, and no real filesystem hands out whole seconds.
var fixedMTime = time.Date(2026, 7, 30, 10, 0, 0, 987654321, time.UTC)

func fingerprint() engine.Fingerprint {
	return engine.Fingerprint{
		SourceSize:  4096,
		SourceMTime: fixedMTime,
		SourceHash:  sha,
	}
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

func TestFirstRunIsEmptyNotAnError(t *testing.T) {
	s := open(t, t.TempDir())
	assert.Equalf(t, 0, s.Len(), "a fresh store should be empty, has %d entries", s.Len())
	assert.True(t, !s.Corrupt(), "a missing document is a first run, not a discarded one")
	if _, ok := s.Get(key("/x/a.jsonl")); ok {
		t.Error("a fresh store should know nothing")
	}
}

func TestCommitThenReload(t *testing.T) {
	dir := t.TempDir()

	s := open(t, dir)
	want := fingerprint()
	require.NoError(t, commit(s, key("/x/a.jsonl"), want))
	s.Close()

	s2 := open(t, dir)
	got, ok := s2.Get(key("/x/a.jsonl"))
	require.True(t, ok, "entry did not survive a reload")
	assert.Truef(t, got.SourceHash == want.SourceHash && got.SourceSize == want.SourceSize, "fingerprint changed across reload:\n got %+v\nwant %+v", got, want)
	if !got.SourceMTime.Equal(want.SourceMTime) {
		t.Errorf("mtime: got %s want %s", got.SourceMTime, want.SourceMTime)
	}
}

// The pre-filter compares stored mtimes for exact equality, so the precision matters: dropping
// sub-second digits makes that branch unreachable and re-reads every file forever.
func TestAStoredMTimeKeepsTheNanosecondsThePreFilterComparesOn(t *testing.T) {
	dir := t.TempDir()
	fp := fingerprint()
	require.NotEqual(t, 0, fp.SourceMTime.Nanosecond(), "the fixture has a whole-second mtime; this test would pass vacuously")

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fp))
	s.Close()

	got, ok := open(t, dir).Get(key("/x/a.jsonl"))
	require.True(t, ok, "entry did not survive a reload")
	if !got.SourceMTime.Equal(fp.SourceMTime) {
		t.Errorf("mtime lost precision across the round trip:\n got %s\nwant %s",
			got.SourceMTime.Format(time.RFC3339Nano), fp.SourceMTime.Format(time.RFC3339Nano))
	}
}

// The flock stops two flushes interleaving, non-blocking: a second flush is told the store is busy.
func TestSecondOpenIsRefusedNotQueued(t *testing.T) {
	dir := t.TempDir()
	first := open(t, dir)
	defer first.Close()

	if _, err := engine.Open(dir, installID); !errors.Is(err, engine.ErrLocked) {
		t.Fatalf("a second open must return ErrLocked, got %v", err)
	}
}

func TestLockIsReleasedOnClose(t *testing.T) {
	dir := t.TempDir()
	s, err := engine.Open(dir, installID)
	require.NoError(t, err)
	require.NoError(t, s.Close())
	s2, err := engine.Open(dir, installID)
	require.NoErrorf(t, err, "the lock was not released: %v", err)
	s2.Close()
}

// status and doctor must not contend with a flush, so Peek takes no lock.
func TestPeekWorksWhileLocked(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))

	doc, err := engine.Peek(dir)
	require.NoErrorf(t, err, "Peek must work while the store is locked: %v", err)
	assert.Lenf(t, doc.Entries, 1, "Peek saw %d entries, want 1", len(doc.Entries))
	assert.Equalf(t, installID, doc.InstallID, "Peek install_id: %q", doc.InstallID)
}

// A crash before the atomic replace leaves the previous document intact: retry is re-run.
func TestCrashBeforeCommitLeavesThePreviousDocument(t *testing.T) {
	dir := t.TempDir()

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()

	before, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)

	// A second store mutates in memory and is abandoned without committing.
	s2 := open(t, dir)
	s2.Get(key("/x/a.jsonl"))
	s2.Close()

	after, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.Equal(t, string(after), string(before), "the document changed without a commit")
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
		if _, err := s.EnsureSpec(id, sha); err != nil {
			t.Fatal(err)
		}
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

func TestCommitAllReplacesOnce(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)

	updates := map[engine.Key]engine.Fingerprint{
		key("/x/a.jsonl"): fingerprint(),
		key("/x/b.jsonl"): fingerprint(),
		key("/x/c.jsonl"): fingerprint(),
	}
	require.NoError(t, s.CommitAll(updates))
	assert.Equalf(t, 3, s.Len(), "expected 3 entries, got %d", s.Len())
	s.Close()

	doc, err := engine.Peek(dir)
	require.NoError(t, err)
	assert.Lenf(t, doc.Entries, 3, "expected 3 entries on disk, got %d", len(doc.Entries))
}

// A wiped document is cheap: the store comes back empty and re-uploads onto existing keys.
func TestWipedDocumentComesBackEmpty(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()

	require.NoError(t, os.Remove(filepath.Join(dir, engine.FileName)))
	s2, err := engine.Open(dir, installID)
	require.NoErrorf(t, err, "a wiped document must not be an error: %v", err)
	defer s2.Close()
	assert.Equalf(t, 0, s2.Len(), "expected an empty store, got %d entries", s2.Len())
}

// A kill -9 mid-flush strands a fingerprints temp. The old fixed name, fingerprints.json.tmp-<pid>,
// wedged every commit once a pid recurred: O_EXCL refused the name until a human deleted the file,
// and every run re-shipped everything. Temp names are random now; this pins the wedge closed.
func TestAStrandedOwnPidTempDoesNotWedgeTheCommit(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, engine.FileName+fmt.Sprintf(".tmp-%d", os.Getpid()))
	require.NoError(t, os.WriteFile(tmp, []byte(`{"half":"written`), 0o600))

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()

	s2 := open(t, dir)
	if _, ok := s2.Get(key("/x/a.jsonl")); !ok {
		t.Fatal("the committed entry did not survive a reload")
	}
}
