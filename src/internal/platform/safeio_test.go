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

func TestReadWhole(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	write(t, p, "{\"a\":1}\n{\"b\":2}\n")

	got, info, err := platform.ReadWhole(p, 0)
	require.NoError(t, err)
	assert.Equalf(t, "{\"a\":1}\n{\"b\":2}\n", string(got), "content: %q", got)
	assert.Equalf(t, int64(len(got)), info.Size(), "stat size %d, read %d bytes", info.Size(), len(got))
}

// A torn final line is data, not an error: it ships byte-exact and nothing here may repair a tail.
func TestReadWholeKeepsATornTailVerbatim(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "torn.jsonl")
	const torn = "{\"a\":1}\n{\"b\":2"
	write(t, p, torn)

	got, _, err := platform.ReadWhole(p, 0)
	require.NoErrorf(t, err, "a truncated last line must not be an error: %v", err)
	assert.Equalf(t, torn, string(got), "tail was altered:\n got %q\nwant %q", got, torn)
}

// The core anti-TOCTOU property: a symlink at the final component is refused, however innocuous its target.
func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.jsonl")
	write(t, real, "{}\n")
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	if _, _, err := platform.Open(link); !errors.Is(err, platform.ErrNotRegular) {
		t.Fatalf("a symlinked path must be refused with ErrNotRegular, got %v", err)
	}
	if _, _, err := platform.ReadWhole(link, 0); !errors.Is(err, platform.ErrNotRegular) {
		t.Fatalf("ReadWhole must refuse a symlink too, got %v", err)
	}
}

// The hazard this exists for: a symlink pointing at credentials, refused on the symlink alone.
func TestOpenRefusesSymlinkToSensitiveTarget(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "credentials.json")
	write(t, secret, `{"access_token":"secret"}`)
	link := filepath.Join(dir, "projects", "innocent.jsonl")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o700))
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	body, _, err := platform.ReadWhole(link, 0)
	require.Errorf(t, err, "read through a symlink returned %d bytes; it must be refused", len(body))
	require.NotContains(t, string(body), "secret", "credential content was returned through a symlink")
}

func TestOpenRefusesDirectory(t *testing.T) {
	if _, _, err := platform.Open(t.TempDir()); !errors.Is(err, platform.ErrNotRegular) {
		t.Fatalf("a directory must be refused with ErrNotRegular, got %v", err)
	}
}

func TestReadWholeHonoursSizeLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.jsonl")
	write(t, p, strings.Repeat("x", 1024))

	if _, _, err := platform.ReadWhole(p, 512); !errors.Is(err, platform.ErrTooLarge) {
		t.Fatalf("over-limit read must return ErrTooLarge, got %v", err)
	}
	// Exactly at the limit is fine: the extra byte detects overflow, it does not reject the boundary case.
	if _, _, err := platform.ReadWhole(p, 1024); err != nil {
		t.Fatalf("a file exactly at the limit must be accepted: %v", err)
	}
}

func TestWriteAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")

	require.NoError(t, platform.WriteAtomic(p, []byte("first"), 0o600))
	require.NoError(t, platform.WriteAtomic(p, []byte("second"), 0o600))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equalf(t, "second", string(got), "content after replace: %q", got)
}

// No temp file may survive a successful write, or every run would leak one alongside each document.
func TestWriteAtomicLeavesNoTempBehind(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, platform.WriteAtomic(filepath.Join(dir, "x.json"), []byte("x"), 0o600))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContainsf(t, e.Name(), ".tmp-", "temp file survived a successful write: %s", e.Name())
	}
	assert.Lenf(t, entries, 1, "expected exactly the target file, got %d entries", len(entries))
}

// The name is fixed and the file is the last run's, so opening it must leave nothing of the previous run behind.
func TestOpenTruncatingEmptiesWhatItOpens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "last-sync.log")
	write(t, p, strings.Repeat("previous run\n", 100))

	f, err := platform.OpenTruncating(p, 0o600)
	require.NoError(t, err)
	if _, err := f.WriteString("this run\n"); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, f.Close())

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equalf(t, "this run\n", string(got), "content after reopen: %q", got)
}

// A fixed name in a world-known directory is the classic symlink target.
func TestOpenTruncatingRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "precious.json")
	write(t, target, `{"keep":"me"}`)
	link := filepath.Join(dir, "last-sync.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	f, err := platform.OpenTruncating(link, 0o600)
	if err == nil {
		f.Close()
		t.Fatal("a symlinked path was opened for truncation")
	}
	assert.ErrorIsf(t, err, platform.ErrNotRegular, "want ErrNotRegular, got %v", err)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equalf(t, `{"keep":"me"}`, string(got), "the symlink's target was truncated: %q", got)
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
	if _, err := os.Stat(stale); err != nil {
		t.Errorf("the stranded temp should be left alone (no cleanup, by decision): %v", err)
	}
}
