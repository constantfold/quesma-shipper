package platform_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// Reads preserve arbitrary bytes, including torn JSONL tails, and accept exactly the configured limit.
func TestReadWholeContract(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		limit      int64
		err        error
	}{
		{"jsonl", "{\"a\":1}\n{\"b\":2}\n", 0, nil},
		{"torn", "{\"a\":1}\n{\"b\":2", 0, nil},
		{"at limit", strings.Repeat("x", 1024), 1024, nil},
		{"over limit", strings.Repeat("x", 1024), 512, platform.ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.jsonl")
			write(t, path, tc.body)
			got, info, err := platform.ReadWhole(path, tc.limit)
			require.ErrorIs(t, err, tc.err)
			if err != nil {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.body, string(got))
			assert.Equal(t, int64(len(got)), info.Size())
		})
	}
}

// Final-component symlinks must neither disclose nor truncate their targets, regardless of what the target contains.
func TestFileOperationsRefuseSymlinks(t *testing.T) {
	for _, tc := range []struct{ target, link, body string }{
		{"real.jsonl", "link.jsonl", "{}\n"},
		{"credentials.json", "projects/innocent.jsonl", `{"access_token":"secret"}`},
		{"precious.json", "last-sync.log", `{"keep":"me"}`},
	} {
		t.Run(tc.target, func(t *testing.T) {
			dir := t.TempDir()
			target, link := filepath.Join(dir, tc.target), filepath.Join(dir, tc.link)
			write(t, target, tc.body)
			require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o700))
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("cannot create symlinks here: %v", err)
			}
			f, _, err := platform.Open(link)
			if f != nil {
				f.Close()
			}
			require.ErrorIs(t, err, platform.ErrNotRegular)
			body, _, err := platform.ReadWhole(link, 0)
			require.ErrorIs(t, err, platform.ErrNotRegular)
			assert.Empty(t, body, "reading through the symlink must disclose nothing")
			f, err = platform.OpenTruncating(link, 0o600)
			if f != nil {
				f.Close()
			}
			require.ErrorIs(t, err, platform.ErrNotRegular)
			body, err = os.ReadFile(target)
			require.NoError(t, err)
			assert.Equal(t, tc.body, string(body), "the symlink target must stay intact")
		})
	}
}

func TestOpenRefusesDirectory(t *testing.T) {
	if _, _, err := platform.Open(t.TempDir()); !errors.Is(err, platform.ErrNotRegular) {
		t.Fatalf("a directory must be refused with ErrNotRegular, got %v", err)
	}
}

func TestWriteAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, body := range []string{"first", "second"} {
		require.NoError(t, platform.WriteAtomic(path, []byte(body), 0o600))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, body, string(got))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "each successful write must remove its temporary file")
		assert.Equal(t, "state.json", entries[0].Name())
	}
}

func TestWriteAtomicCleansUpAFailedRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(path, 0o700))
	require.ErrorContains(t, platform.WriteAtomic(path, []byte("new"), 0o600), "rename temp")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "a failed write must remove its temporary file")
	assert.Equal(t, "blocked", entries[0].Name())
	assert.True(t, entries[0].IsDir(), "the original target must remain intact")
}

// The name is fixed and the file is the last run's, so opening it must leave nothing of the previous run behind.
func TestOpenTruncatingEmptiesWhatItOpens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "last-sync.log")
	write(t, p, strings.Repeat("previous run\n", 100))

	f, err := platform.OpenTruncating(p, 0o600)
	require.NoError(t, err)
	_, writeStringErr := f.WriteString("this run\n")
	require.NoError(t, writeStringErr)
	require.NoError(t, f.Close())

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equalf(t, "this run\n", string(got), "content after reopen: %q", got)
}

// A stranded temp from a crashed run must never block a later write: the temp name is random,
// never derived from the pid, so a recurring pid cannot recreate the name. There is no cleanup,
// by decision: the leftover is inert garbage and stays.
func TestWriteAtomicIsNotWedgedByAStrandedTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	stale := fmt.Sprintf("%s.tmp-%d", p, os.Getpid())
	require.NoError(t, os.WriteFile(stale, []byte("{half"), 0o600))

	require.NoError(t, platform.WriteAtomic(p, []byte("fresh"), 0o600))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equalf(t, "fresh", string(got), "content: got %q want %q", got, "fresh")
	_, statErr := os.Stat(stale)
	assert.NoErrorf(t, statErr, "the stranded temp should be left alone (no cleanup, by decision): %v", statErr)
}
