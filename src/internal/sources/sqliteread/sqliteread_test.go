package sqliteread_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
)

// newStore builds a state.vscdb-shaped fixture: two key/value tables as Cursor has, planting the rows the filter must catch.
func newStore(t *testing.T, rows map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.vscdb")
	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);
		CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`)
	require.NoError(t, err)
	for k, v := range rows {
		// Auth keys go where Cursor keeps them, the table the enricher does NOT declare.
		table := "cursorDiskKV"
		if strings.HasPrefix(k, "cursorAuth/") {
			table = "ItemTable"
		}
		_, err := db.Exec(`INSERT INTO `+table+` (key, value) VALUES (?, ?)`, k, v)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	return path
}

func read(t *testing.T, path string, opts ...func(*sqliteread.Options)) sqliteread.Result {
	t.Helper()
	o := sqliteread.Options{
		Path:        path,
		ScratchDir:  filepath.Join(t.TempDir(), "scratch"),
		Table:       "cursorDiskKV",
		KeyPrefixes: []string{"composerData:", "bubbleId:"},
	}
	for _, f := range opts {
		f(&o)
	}
	res, err := sqliteread.Read(o)
	require.NoErrorf(t, err, "read: %v", err)
	return res
}

// One store checks scope, exact values, ordering, and the rule against writes beside the source.
func TestDeclaredReadContract(t *testing.T) {
	const verbatim = `{"z":1,"a":2,"m":{"y":3,"b":4}}`
	path := newStore(t, map[string]string{
		"composerData:c1":       `{"composerId":"c1"}`,
		"bubbleId:c1:b1":        `{"type":1,"text":"hello"}`,
		"bubbleId:c1:b2":        `{"type":2}`,
		"bubbleId:c1:b3":        `{"type":2}`,
		"composerData:nested":   `{"a":{"b":{"c":[{"blobEncryptionKey":"KEYMATERIAL-DEEP"}]}}}`,
		"composerData:verbatim": verbatim,
		"checkpointId:c1:x":     `{"secret":"not this enricher's business"}`,
		"messageRequestContext": `{"also":"no"}`,
	})
	want := []sqliteread.Row{
		{Key: "bubbleId:c1:b1", Value: []byte(`{"type":1,"text":"hello"}`)},
		{Key: "bubbleId:c1:b2", Value: []byte(`{"type":2}`)},
		{Key: "bubbleId:c1:b3", Value: []byte(`{"type":2}`)},
		{Key: "composerData:c1", Value: []byte(`{"composerId":"c1"}`)},
		{Key: "composerData:nested", Value: []byte(`{"a":{"b":{"c":[{}]}}}`)},
		{Key: "composerData:verbatim", Value: []byte(verbatim)},
	}
	dir := filepath.Dir(path)
	before := listDir(t, dir)
	t.Run("scope, contents and stable order", func(t *testing.T) {
		for range 2 {
			res := read(t, path)
			assert.Equal(t, sqliteread.ReadInPlace, res.Method)
			assert.Equal(t, want, res.Rows)
		}
	})
	t.Run("narrow scope never writes beside the source", func(t *testing.T) {
		scratch := filepath.Join(t.TempDir(), "scratch")
		for range 3 {
			res := read(t, path, func(o *sqliteread.Options) {
				o.ScratchDir = scratch
				o.KeyPrefixes = []string{"composerData:"}
			})
			assert.Equal(t, want[3:], res.Rows)
		}
		assert.Equal(t, before, listDir(t, dir))
	})
	t.Run("LIKE wildcards are literal", func(t *testing.T) {
		res := read(t, path, func(o *sqliteread.Options) { o.KeyPrefixes = []string{"%"} })
		assert.Empty(t, res.Rows)
	})
	assert.Equal(t, before, listDir(t, dir))
}

// The exact-key exceptions, stated in both directions: the four named keys pass, and a token key never does.
func TestTheAuthNamespaceExceptionsAreExactKeysOnly(t *testing.T) {
	const token = "SUPER-SECRET-CURSOR-SESSION-TOKEN"
	path := newStore(t, map[string]string{
		"cursorAuth/stripeMembershipType": "enterprise",
		"cursorAuth/cachedEmail":          "dev@example.com",
		"cursorAuth/cachedSignUpType":     "Google",
		"cursorAuth/cachedTeam":           `{"teamId": 1, "name": "Quesma"}`,
		"cursorAuth/accessToken":          token,
		"cursorAuth/refreshToken":         token,
		// A prefix of an allowed key is NOT allowed: exactness is the guarantee.
		"cursorAuth/cachedEmailBackup": token,
	})
	res := read(t, path, func(o *sqliteread.Options) {
		o.Table = "ItemTable" // where Cursor keeps the cursorAuth namespace
		o.KeyPrefixes = []string{"cursorAuth/"}
	})
	assert.Equal(t, []sqliteread.Row{
		{Key: "cursorAuth/cachedEmail", Value: []byte("dev@example.com")},
		{Key: "cursorAuth/cachedSignUpType", Value: []byte("Google")},
		{Key: "cursorAuth/cachedTeam", Value: []byte(`{"teamId": 1, "name": "Quesma"}`)},
		{Key: "cursorAuth/stripeMembershipType", Value: []byte("enterprise")},
	}, res.Rows)
}

// THE FILTER TEST. Auth material lives in the same database as the trajectories.
func TestTheCompiledFilterStripsAuthKeysAndEncryptionKeyFields(t *testing.T) {
	const token = "SUPER-SECRET-CURSOR-SESSION-TOKEN"
	path := newStore(t, map[string]string{
		// One auth key per table and spelling: neither the table split nor the case may let one through.
		"cursorAuth/accessToken": token,
		"CursorAuth/cased":       token,
		// The encryption-key fields, nested where they really appear.
		"composerData:c1": `{"composerId":"c1","blobEncryptionKey":"` + token + `",` +
			`"speculativeSummarizationEncryptionKey":"` + token + `",` +
			`"fullConversationHeadersOnly":[{"bubbleId":"b1","type":1}]}`,
		"bubbleId:c1:b1": `{"type":1,"text":"hi","nested":{"blobEncryptionKey":"` + token + `"}}`,
	})

	res := read(t, path, func(o *sqliteread.Options) {
		// Deliberately declaring the auth namespace too: the filter is compiled, not something a declaration overrides.
		o.KeyPrefixes = []string{"composerData:", "bubbleId:", "cursorAuth/", "CursorAuth/"}
	})
	// Only the two trajectory rows survive, re-encoded where a field was stripped.
	assert.Equal(t, []sqliteread.Row{
		{Key: "bubbleId:c1:b1", Value: []byte(`{"nested":{},"text":"hi","type":1}`)},
		{Key: "composerData:c1", Value: []byte(`{"composerId":"c1","fullConversationHeadersOnly":[{"bubbleId":"b1","type":1}]}`)},
	}, res.Rows)
}

// Unreadable databases fail through every fallback; a live database must also refuse raw copying.
func TestUnreadableDatabaseFallbacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	for _, tc := range []struct {
		name, want string
		prepare    func(*testing.T, string, string)
	}{
		{"all methods fail", "every read method failed", func(t *testing.T, path, scratch string) {
			inPlace := read(t, path, func(o *sqliteread.Options) { o.ScratchDir = scratch })
			require.Equal(t, sqliteread.ReadInPlace, inPlace.Method, "expected the fast path first")
		}},
		{"live database cannot be copied", "not cold enough", func(t *testing.T, path, _ string) {
			require.NoError(t, os.Chtimes(path, time.Now(), time.Now()))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
			scratch := filepath.Join(t.TempDir(), "scratch")
			tc.prepare(t, path, scratch)
			if err := os.Chmod(path, 0o000); err != nil {
				t.Skipf("cannot chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			_, err := sqliteread.Read(sqliteread.Options{Path: path, ScratchDir: scratch, Table: "cursorDiskKV"})
			require.ErrorContains(t, err, tc.want, "an unreadable database produced a successful read")
		})
	}
}

// THE SIDECAR BASENAME RULE. A mistake this project already made once.
func TestColdCopyKeepsSidecarsAndRefusesOverwrite(t *testing.T) {
	src := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
	for _, suffix := range []string{"-wal", "-shm"} {
		require.NoError(t, os.WriteFile(src+suffix, []byte("sidecar"), 0o600))
	}

	dst := t.TempDir()
	copied, err := sqliteread.CopyCold(src, dst)
	require.NoError(t, err)

	// A copy that omits or RENAMES the -wal opens without the WAL's contents, since SQLite finds the sidecar by basename.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		assert.FileExists(t, copied+suffix, "did not land beside the copy")
	}
	assert.Equalf(t, filepath.Base(src), filepath.Base(copied), "the copy was renamed: %s vs %s", filepath.Base(copied), filepath.Base(src))
	// Overwriting could mix a fresh database with stale sidecars.
	_, err = sqliteread.CopyCold(src, dst)
	require.Error(t, err, "a cold copy overwrote an existing target")
}

func TestAnUndeclaredTableIsRefused(t *testing.T) {
	path := newStore(t, map[string]string{"composerData:c1": `{}`})
	_, err := sqliteread.Read(sqliteread.Options{Path: path, ScratchDir: t.TempDir()})
	// Scope is declared: a read with no table is a programming fault, not something to guess at.
	require.Error(t, err, "a read with no declared table was accepted")
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// Every read method returns identical rows and leaves the source alone; a snapshot replaces crash debris and cleans up.
func TestEveryReadMethodReturnsIdenticalRowsAndCleansUp(t *testing.T) {
	path := newStore(t, map[string]string{
		"composerData:c1": `{"composerId":"c1","fullConversationHeadersOnly":[{"bubbleId":"b1","type":1}]}`,
		"bubbleId:c1:b1":  `{"type":1,"text":"hello","createdAt":"2026-07-30T10:00:00Z"}`,
		"bubbleId:c1:b2":  `{"type":2,"text":"world","createdAt":"2026-07-30T10:00:01Z"}`,
	})
	// Old enough for the cold copy to accept it.
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	before := listDir(t, filepath.Dir(path))
	var reference []sqliteread.Row
	for _, want := range []sqliteread.ReadMethod{sqliteread.ReadInPlace, sqliteread.ReadSnapshot, sqliteread.ReadColdCopy} {
		scratch := filepath.Join(t.TempDir(), "scratch")
		leftover := filepath.Join(scratch, "snapshot-state.vscdb.sqlite")
		require.NoError(t, os.MkdirAll(scratch, 0o700))
		require.NoError(t, os.WriteFile(leftover, []byte("corrupt partial"), 0o600))

		res := read(t, path, func(o *sqliteread.Options) { o.ScratchDir, o.StartAt = scratch, want })
		require.Equalf(t, want, res.Method, "asked for method %s, got %s", want, res.Method)
		assert.Equal(t, before, listDir(t, filepath.Dir(path)), "method %s changed the source directory", want)
		if want == sqliteread.ReadSnapshot {
			assert.Empty(t, listDir(t, scratch))
		} else {
			body, err := os.ReadFile(leftover)
			require.NoError(t, err)
			assert.Equal(t, "corrupt partial", string(body), "method %s touched the snapshot slot", want)
			assert.Equal(t, []string{"snapshot-state.vscdb.sqlite"}, listDir(t, scratch))
		}
		if reference == nil {
			reference = res.Rows
			continue
		}
		assert.Equal(t, reference, res.Rows, "method %s", want)
	}
	assert.Len(t, reference, 3)
}
