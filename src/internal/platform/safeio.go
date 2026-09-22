// Package platform is the shipper's only file-open path: reads never follow a final-component
// symlink and are checked by fstat on the descriptor, not the name; durable writes commit by
// rename. O_NOFOLLOW covers only the final component, the compiled deny list covers the rest.
package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrNotRegular is returned when a path is not a regular file, including a symlink refused by O_NOFOLLOW.
var ErrNotRegular = errors.New("safeio: not a regular file")

// ErrTooLarge is returned when a file exceeds the caller's byte budget; the file is left alone.
var ErrTooLarge = errors.New("safeio: file exceeds size limit")

// Open refuses a final-component symlink; the FileInfo is the descriptor's fstat, so never re-stat the path.
func Open(path string) (*os.File, os.FileInfo, error) {
	return openRegular(path, os.O_RDONLY, 0)
}

// openRegular refuses anything but a regular file by fstat on the descriptor, never the name.
func openRegular(path string, flag int, perm os.FileMode) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, flag|openFlags, perm)
	switch {
	case errors.Is(err, syscall.ELOOP):
		return nil, nil, fmt.Errorf("%w: %s is a symlink", ErrNotRegular, path)
	case errors.Is(err, syscall.ENXIO):
		return nil, nil, fmt.Errorf("%w: %s is a fifo", ErrNotRegular, path)
	case err != nil:
		return nil, nil, fmt.Errorf("safeio: open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("safeio: fstat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %s is %s", ErrNotRegular, path, info.Mode().Type())
	}
	return f, info, nil
}

// ReadWhole reads a whole file through Open; maxBytes of zero means no limit.
func ReadWhole(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	f, info, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if maxBytes > 0 {
		if info.Size() > maxBytes {
			return nil, info, fmt.Errorf("%w: %s is %d bytes, limit %d",
				ErrTooLarge, path, info.Size(), maxBytes)
		}
		r = io.LimitReader(f, maxBytes+1)
	}

	var buf bytes.Buffer
	// fstat already gave the exact size; grow by it plus MinRead so the final EOF probe does not trigger geometric growth.
	if size := info.Size(); size > 0 && size <= int64(math.MaxInt-bytes.MinRead) {
		buf.Grow(int(size) + bytes.MinRead)
	}
	_, err = buf.ReadFrom(r)
	if err != nil {
		return nil, info, fmt.Errorf("safeio: read %s: %w", path, err)
	}
	body := buf.Bytes()
	if maxBytes > 0 && int64(len(body)) > maxBytes {
		return nil, info, fmt.Errorf("%w: %s grew past the limit %d during the read",
			ErrTooLarge, path, maxBytes)
	}
	return body, info, nil
}

// ReadPrivate refuses key material whose mode was loosened, never repairing it silently.
func ReadPrivate(path string, maxBytes int64) ([]byte, error) {
	raw, info, err := ReadWhole(path, maxBytes)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); platformSupportsFileModes && perm&0o077 != 0 {
		return nil, fmt.Errorf("safeio: %s has mode %#o: must not be group- or world-accessible", path, perm)
	}
	return raw, nil
}

// WriteJSON writes v as an indented JSON document via WriteAtomic: the one spelling of "save a small state file".
func WriteJSON(path string, v any, perm os.FileMode) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("safeio: encode %s: %w", path, err)
	}
	return WriteAtomic(path, append(body, '\n'), perm)
}

// EnsureDir creates a directory tree owned by the shipper; perm is applied explicitly so an ambient umask cannot widen it.
func EnsureDir(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("safeio: create dir %s: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("safeio: chmod dir %s: %w", path, err)
	}
	return nil
}

// OpenTruncating is the one non-atomic write, for the run log's live tail; O_NONBLOCK refuses a planted fifo
// that would hang the sync under the store lock, and it truncates only after fstat confirms a regular file.
func OpenTruncating(path string, perm os.FileMode) (*os.File, error) {
	f, _, err := openRegular(path, os.O_WRONLY|os.O_CREATE|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return nil, fmt.Errorf("safeio: chmod %s: %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, fmt.Errorf("safeio: truncate %s: %w", path, err)
	}
	return f, nil
}

// WriteAtomic commits by rename. The temp name is random, so a temp stranded by a crash can never block a later
// write, and CreateTemp's O_EXCL refuses a planted name, symlink included.
func WriteAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("safeio: create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("safeio: write temp for %s: %w", path, err)
	}
	// fsync before rename: a rename that lands before the data is durable can leave an empty file after a crash.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("safeio: fsync temp for %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("safeio: close temp for %s: %w", path, err)
	}
	// Chmod explicitly: CreateTemp always creates 0600, and the caller's perm must hold past the umask.
	if err := os.Chmod(tmp, perm); err != nil {
		return fmt.Errorf("safeio: chmod temp for %s: %w", path, err)
	}
	// Windows refuses to replace a file another handle has open; readers are brief, so retry.
	for attempt := 1; ; attempt++ {
		if err = os.Rename(tmp, path); err == nil {
			break
		}
		if attempt == 5 {
			return fmt.Errorf("safeio: rename temp for %s: %w", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	syncDir(dir)
	return nil
}

// maxLogBytes is where a log rotates; PreviousLogSuffix names the one generation kept past it.
const (
	maxLogBytes       = 8 << 20
	PreviousLogSuffix = ".1"
)

// RotateLog renames rather than truncates, since an open writer keeps its offset; failures never fail the write.
func RotateLog(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() < maxLogBytes {
		return
	}
	_ = os.Rename(path, path+PreviousLogSuffix)
}

// syncDir makes a rename durable. Best-effort: some filesystems refuse to open a directory for sync.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
