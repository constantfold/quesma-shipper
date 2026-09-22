package auditlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A large log must return the newest entries while reading only its tail.
func TestTailingALargeLogReadsOnlyTheEndOfIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	f, err := os.Create(path)
	require.NoError(t, err)
	pad := strings.Repeat("y", 2<<10)
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(f, `{"at":"2026-08-06T00:00:00Z","decision":"unchanged","file":"f%05d","reason":"%s"}`+"\n", i, pad)
	}
	f.Close()

	info, err := os.Stat(path)
	require.NoError(t, err)
	size := info.Size()
	require.Truef(t, size >= 30<<20, "the fixture is only %d bytes; it cannot show the difference", size)

	bytesRead.Store(0)
	entries, err := Tail(path, 3)
	read := bytesRead.Load()
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "f19999", entries[2].File, "last entry must be the newest line")
	assert.Equal(t, "f19997", entries[0].File, "first entry must be the third newest line")

	if read > 1<<20 {
		t.Errorf("tailing 3 lines from a %d byte log read %d bytes; it should read the end, "+
			"not the file", size, read)
	}
	assert.NotEqual(t, int64(0), read, "nothing was read; the counter is not wired and this test proves nothing")
}
