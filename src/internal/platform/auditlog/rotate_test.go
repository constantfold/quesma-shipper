package auditlog_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// Unrotated, `quesma-shipper log tail` stops working past the read cap, on the installs with the most to explain.
func TestTheLogRotatesInsteadOfGrowingForever(t *testing.T) {
	dir := t.TempDir()
	l, err := auditlog.Open(dir)
	require.NoError(t, err)

	// Enough entries to pass the threshold; sanitize truncates Reason, so padding reaches disk far smaller.
	pad := strings.Repeat("x", 512)
	for i := 0; i < 40000; i++ {
		require.NoError(t, l.Append(auditlog.Entry{
			Decision: auditlog.DecisionUnchanged,
			SourceID: "claude-code-transcripts",
			File:     fmt.Sprintf("projects/p/%04d.jsonl", i),
			Reason:   pad,
		}))
	}

	current := size(t, filepath.Join(dir, auditlog.FileName))
	previous := size(t, filepath.Join(dir, auditlog.FileName+".1"))

	require.NotEqual(t, int64(0), previous, "nothing rotated; the log grows without bound")
	assert.Truef(t, current <= 16<<20, "the current log is %d bytes, well past the rotation threshold", current)
	// Two generations, no more: the disk cost is bounded and the most recent history survives a rotation.
	if _, err := os.Stat(filepath.Join(dir, auditlog.FileName+".2")); err == nil {
		t.Error("a third generation exists; two is the whole design")
	}
}

// Tailing must work at any size, and must not read the whole file to answer.
func TestTailReadsFromTheEndOfALargeLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, auditlog.FileName)

	// 40 MiB, well past anything worth loading to answer "what were the last three things".
	f, err := os.Create(path)
	require.NoError(t, err)
	pad := strings.Repeat("y", 2<<10)
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(f, `{"at":"2026-08-06T00:00:00Z","decision":"unchanged","file":"f%05d","reason":"%s"}`+"\n", i, pad)
	}
	f.Close()

	entries, err := auditlog.Tail(path, 3)
	require.NoErrorf(t, err, "tailing a large log failed: %v", err)
	require.Lenf(t, entries, 3, "want 3 entries, got %d", len(entries))
	assert.Equalf(t, "f19999", entries[2].File, "last entry is %q, want the newest line f19999", entries[2].File)
	assert.Equalf(t, "f19997", entries[0].File, "first of the three is %q, want f19997", entries[0].File)
}

// A tail that spans a rotation must still answer, or the rotation creates a blind window exactly when someone looks.
func TestTailReachesIntoThePreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, auditlog.FileName)

	write(t, path+".1", "older-1", "older-2", "older-3")
	write(t, path, "newer-1")

	entries, err := auditlog.Tail(path, 3)
	require.NoError(t, err)
	require.Lenf(t, entries, 3, "want 3 entries across the rotation, got %d", len(entries))
	assert.Equalf(t, "newer-1", entries[len(entries)-1].File, "newest is %q, want newer-1", entries[len(entries)-1].File)
	assert.Equalf(t, "older-2", entries[0].File, "oldest of the three is %q, want older-2", entries[0].File)
}

func write(t *testing.T, path string, files ...string) {
	t.Helper()
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, `{"at":"2026-08-06T00:00:00Z","decision":"unchanged","file":%q}`+"\n", f)
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
}

func size(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
