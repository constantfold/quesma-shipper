package auditlog

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// readTail returns the last n lines, reading backwards from the END; the previous generation is consulted only when needed.
func readTail(path string, n int) ([]byte, error) {
	if n <= 0 {
		n = defaultTailLines
	}
	cur, err := tailFile(path, n)
	if err != nil {
		return nil, err
	}
	have := bytes.Count(cur, []byte{'\n'})
	if have >= n {
		return cur, nil
	}
	// Not enough in the current file: the rest is in the generation before it, if there is one.
	prev, err := tailFile(path+platform.PreviousLogSuffix, n-have)
	if err != nil || len(prev) == 0 {
		return cur, nil
	}
	return append(prev, cur...), nil
}

const (
	defaultTailLines = 200      // bounds a tail with no explicit count; without it, n=0 means the whole file
	tailChunk        = 64 << 10 // how much is read per backwards step
)

// bytesRead counts what the backwards reader pulled off disk: the cost-is-the-answer property a test can assert on.
var bytesRead atomic.Int64

func tailFile(path string, n int) ([]byte, error) {
	// os.Open on purpose, not safeio: an operator may symlink the log elsewhere.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()

	var buf []byte
	newlines := 0
	pos := size
	for pos > 0 && newlines <= n {
		step := min(int64(tailChunk), pos)
		pos -= step

		chunk := make([]byte, step)
		if _, err := f.ReadAt(chunk, pos); err != nil && err != io.EOF {
			return nil, fmt.Errorf("auditlog: read at %d: %w", pos, err)
		}
		bytesRead.Add(step)
		buf = append(chunk, buf...)
		newlines = bytes.Count(buf, []byte{'\n'})
	}

	// A partial first line, where the chunk boundary landed mid-record, is dropped: half a JSON object is not an entry.
	return lastLines(buf, n), nil
}

// lastLines returns the trailing n complete lines of b.
func lastLines(b []byte, n int) []byte {
	i := len(bytes.TrimSuffix(b, []byte{'\n'}))
	for ; n > 0; n-- {
		if i = bytes.LastIndexByte(b[:i], '\n'); i < 0 {
			return b
		}
	}
	return b[i+1:]
}
