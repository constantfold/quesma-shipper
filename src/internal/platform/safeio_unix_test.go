//go:build unix

package platform_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// The mode is explicit rather than left to umask: the identity unit and the run log must stay private.
func TestWritesSetModeRegardlessOfUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	dir := t.TempDir()
	require.NoError(t, platform.WriteAtomic(filepath.Join(dir, "secret.json"), []byte("x"), 0o600))
	f, err := platform.OpenTruncating(filepath.Join(dir, "last-sync.log"), 0o600)
	require.NoError(t, err)
	f.Close()
	for _, name := range []string{"secret.json", "last-sync.log"} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm(), name)
	}
}

// A readerless fifo HANGS a blocking open inside the store lock, so the open itself must refuse it;
// with a reader attached the open succeeds, so the refusal comes from the fstat check instead.
func TestOpenTruncatingRefusesFifo(t *testing.T) {
	for _, withReader := range []bool{false, true} {
		pipe := filepath.Join(t.TempDir(), "last-sync.log")
		if err := syscall.Mkfifo(pipe, 0o600); err != nil {
			t.Skipf("cannot create fifos here: %v", err)
		}
		if withReader {
			r, err := os.OpenFile(pipe, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			require.NoError(t, err)
			defer r.Close()
		}
		var f *os.File
		var err error
		done := make(chan struct{})
		go func() { f, err = platform.OpenTruncating(pipe, 0o600); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("OpenTruncating blocked on a fifo instead of refusing it")
		}
		if err == nil {
			f.Close()
		}
		assert.ErrorIsf(t, err, platform.ErrNotRegular, "reader=%v: want ErrNotRegular, got %v", withReader, err)
	}
}

// A partial write must never be visible under the target name: the rename is the commit point.
func TestWriteAtomicNeverExposesPartialContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	require.NoError(t, platform.WriteAtomic(p, []byte("good"), 0o600))

	// A read-only directory fails the write before any rename can land.
	require.NoError(t, os.Chmod(dir, 0o500))
	defer os.Chmod(dir, 0o700)

	require.Error(t, platform.WriteAtomic(p, []byte("newer"), 0o600), "an unwritable directory should surface as an error, not a silent overwrite")
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equalf(t, "good", string(got), "the previous content must survive a failed write, got %q", got)
}
