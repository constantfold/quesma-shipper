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
	dir := t.TempDir()
	path := filepath.Join(dir, "state.vscdb")

	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer db.Close()

	for _, stmt := range []string{
		`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`,
		`CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`,
	} {
		_, execErr := db.Exec(stmt)
		require.NoError(t, execErr)
	}
	for k, v := range rows {
		table := "cursorDiskKV"
		if strings.HasPrefix(k, "cursorAuth/") {
			// Planted in the table the enricher does NOT declare, and again below in the one it does.
			table = "ItemTable"
		}
		_, insertErr := db.Exec(`INSERT INTO `+table+` (key, value) VALUES (?, ?)`, k, v)
		require.NoError(t, insertErr)
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

// One store pins scope, exact values, ordering, and the rule against writes beside the source.
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
	got := map[string]string{}
	for _, r := range res.Rows {
		got[r.Key] = string(r.Value)
	}
	assert.Equal(t, map[string]string{
		"cursorAuth/stripeMembershipType": "enterprise",
		"cursorAuth/cachedEmail":          "dev@example.com",
		"cursorAuth/cachedSignUpType":     "Google",
		"cursorAuth/cachedTeam":           `{"teamId": 1, "name": "Quesma"}`,
	}, got)
}

// THE FILTER TEST. Auth material lives in the same database as the trajectories.
func TestTheCompiledFilterStripsAuthKeysAndEncryptionKeyFields(t *testing.T) {
	const token = "SUPER-SECRET-CURSOR-SESSION-TOKEN"
	path := newStore(t, map[string]string{
		// In ItemTable, where Cursor keeps it.
		"cursorAuth/accessToken": token,
		// And in the declared table, spelled two ways, so the filter is not passing by table split or by one spelling.
		"cursorAuth/refreshToken": token,
		"CursorAuth/cased":        token,

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

	want := map[string]string{
		"composerData:c1": `{"composerId":"c1","fullConversationHeadersOnly":[{"bubbleId":"b1","type":1}]}`,
		"bubbleId:c1:b1":  `{"type":1,"text":"hi","nested":{}}`,
	}
	require.Len(t, res.Rows, len(want), "only the two trajectory rows may survive")
	for _, r := range res.Rows {
		require.Contains(t, want, r.Key)
		assert.JSONEq(t, want[r.Key], string(r.Value))
		delete(want, r.Key)
	}
	assert.Empty(t, want)
	assert.NotZero(t, res.DeniedKeys, "denied keys must be reported")
	assert.NotZero(t, res.StrippedFields, "stripped fields must be reported")
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
			require.Error(t, err, "an unreadable database produced a successful read")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// THE SIDECAR BASENAME RULE. A mistake this project already made once.
func TestColdCopyKeepsSidecarsAndRefusesOverwrite(t *testing.T) {
	src := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
	// Give it a WAL and an SHM, as a live database has.
	for _, suffix := range []string{"-wal", "-shm"} {
		require.NoError(t, os.WriteFile(src+suffix, []byte("sidecar"), 0o600))
	}

	dst := t.TempDir()
	copied, err := sqliteread.CopyCold(src, dst)
	require.NoError(t, err)

	// A copy that omits or RENAMES the -wal opens without the WAL's contents, since SQLite finds the sidecar by basename.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		want := copied + suffix
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s did not land beside the copy: %v", filepath.Base(want), err)
		}
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

// Every read method returns identical row values, which is why hashes come from values and not bytes. Each
// method leaves the source directory alone; a snapshot replaces crash debris and removes its own copy.
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
