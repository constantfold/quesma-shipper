package engine

import (
	"cmp"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An unloadable document is discarded, not fatal: the run starts empty and the first flush replaces it.
func TestAnUnloadableDocumentIsDiscardedAndReplaced(t *testing.T) {
	const install = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	valid := `{"state_schema": 1, "install_id": "` + install + `", "entries": []}`
	for _, c := range []struct {
		name, body string
		maxBytes   int64
		unreadable bool
	}{
		{name: "invalid JSON", body: "{not json"},
		{name: "state_schema mismatch", body: `{"state_schema": 2, "entries": []}`},
		{name: "checksum mismatch", body: `{"state_schema": 1, "checksum": "deadbeef", "entries": []}`},
		// Its entries name objects under another key root, so not one may survive into this install.
		{name: "another install", body: `{"state_schema": 1, "install_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", ` +
			`"entries": [{"source_id": "s", "native_path": "/x/a.jsonl", "source_hash": "` + strings.Repeat("a", 64) + `"}]}`},
		{name: "negative attempts", body: `{"state_schema": 1, "entries": [{"source_id": "s", "native_path": "/x/a.jsonl", "attempts": -5}]}`},
		{name: "oversize", body: valid, maxBytes: 8},
		{name: "unreadable", body: valid, unreadable: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.unreadable && (runtime.GOOS == "windows" || os.Geteuid() == 0) {
				t.Skip("file modes do not deny the owner here")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, FileName)
			require.NoError(t, os.WriteFile(path, []byte(c.body), 0o600))
			if c.unreadable {
				require.NoError(t, os.Chmod(path, 0o000))
			}

			s, err := open(dir, install, cmp.Or(c.maxBytes, maxDocumentBytes))
			require.NoErrorf(t, err, "open must succeed over a document it cannot load: %v", err)
			require.Truef(t, s.Len() == 0 && s.Corrupt(), "len=%d corrupt=%v, want an empty discarded store", s.Len(), s.Corrupt())
			k := Key{SourceID: "s", NativePath: "/x/b.jsonl"}
			fp := Fingerprint{SourceSize: 1, SourceMTime: time.Unix(1, 0).UTC(), SourceHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
			require.NoError(t, s.CommitAll(map[Key]Fingerprint{k: fp}))
			s.Close()

			s2, err := Open(dir, install)
			require.NoErrorf(t, err, "reopen: %v", err)
			defer s2.Close()
			require.Truef(t, !s2.Corrupt() && s2.Len() == 1, "after the replace: corrupt=%v len=%d, want a clean store of one", s2.Corrupt(), s2.Len())
			got, ok := s2.Get(k)
			assert.Truef(t, ok && got == fp, "the committed entry did not survive the replace: %+v ok=%v", got, ok)
		})
	}
}
