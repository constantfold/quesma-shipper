package sqliteread_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
)

// newStore builds a state.vscdb-shaped fixture: two key/value tables as Cursor has, planting the rows the filter must catch.
func newStore(t *testing.T, rows map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.vscdb")

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, stmt := range []string{
		`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`,
		`CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range rows {
		table := "cursorDiskKV"
		if strings.HasPrefix(k, "cursorAuth/") {
			// Planted in the table the enricher does NOT declare, and again below in the one it does.
			table = "ItemTable"
		}
		if _, err := db.Exec(`INSERT INTO `+table+` (key, value) VALUES (?, ?)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return res
}

// Each case reads its own store: three reads must each return exactly these rows by the fast path, and write nothing beside the source.
func TestAReadReturnsExactlyTheDeclaredRows(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rows     map[string]string
		prefixes []string // nil keeps read's default scope
		want     []sqliteread.Row
	}{
		{
			name: "the fast path reads in place",
			rows: map[string]string{
				"composerData:c1": `{"composerId":"c1"}`,
				"bubbleId:c1:b1":  `{"type":1,"text":"hello"}`,
			},
			want: []sqliteread.Row{
				{Key: "bubbleId:c1:b1", Value: []byte(`{"type":1,"text":"hello"}`)},
				{Key: "composerData:c1", Value: []byte(`{"composerId":"c1"}`)},
			},
		},
		{
			// Scope is declared at registration, not discovered: returning the whole table would make the declaration decorative.
			name: "the declared scope is the only thing read",
			rows: map[string]string{
				"composerData:c1":       `{"composerId":"c1"}`,
				"bubbleId:c1:b1":        `{"type":1}`,
				"checkpointId:c1:x":     `{"secret":"not this enricher's business"}`,
				"messageRequestContext": `{"also":"no"}`,
			},
			want: []sqliteread.Row{
				{Key: "bubbleId:c1:b1", Value: []byte(`{"type":1}`)},
				{Key: "composerData:c1", Value: []byte(`{"composerId":"c1"}`)},
			},
		},
		{
			// Nested inside arrays inside objects, as the real fields are: a shallow filter would pass this.
			name: "nested encryption keys are stripped at any depth",
			rows: map[string]string{
				"composerData:c1": `{"a":{"b":{"c":[{"blobEncryptionKey":"KEYMATERIAL-DEEP"}]}}}`,
			},
			want: []sqliteread.Row{
				{Key: "composerData:c1", Value: []byte(`{"a":{"b":{"c":[{}]}}}`)},
			},
		},
		{
			// Byte-identical, not re-encoded: reordered keys would make the output hash re-ship on every run.
			name: "rows that need no stripping are returned verbatim",
			rows: map[string]string{"composerData:c1": `{"z":1,"a":2,"m":{"y":3,"b":4}}`},
			want: []sqliteread.Row{
				{Key: "composerData:c1", Value: []byte(`{"z":1,"a":2,"m":{"y":3,"b":4}}`)},
			},
		},
		{
			// Determinism starts here: a varying read order would vary the derived output bytes and the output hash with them.
			name: "rows come back in a stable order",
			rows: map[string]string{
				"bubbleId:c1:b3":  `{"type":2}`,
				"bubbleId:c1:b1":  `{"type":1}`,
				"bubbleId:c1:b2":  `{"type":2}`,
				"composerData:c1": `{"composerId":"c1"}`,
			},
			want: []sqliteread.Row{
				{Key: "bubbleId:c1:b1", Value: []byte(`{"type":1}`)},
				{Key: "bubbleId:c1:b2", Value: []byte(`{"type":2}`)},
				{Key: "bubbleId:c1:b3", Value: []byte(`{"type":2}`)},
				{Key: "composerData:c1", Value: []byte(`{"composerId":"c1"}`)},
			},
		},
		{
			// A prefix containing % must not sweep in every key: declared scope has to mean what it says.
			name: "a LIKE wildcard in a prefix matches literally",
			rows: map[string]string{
				"composerData:c1": `{"composerId":"c1"}`,
				"bubbleId:c1:b1":  `{"type":1}`,
			},
			prefixes: []string{"%"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := newStore(t, tc.rows)
			dir := filepath.Dir(path)
			scratch := filepath.Join(t.TempDir(), "scratch")
			before := listDir(t, dir)

			for range 3 {
				res := read(t, path, func(o *sqliteread.Options) {
					o.ScratchDir = scratch
					if tc.prefixes != nil {
						o.KeyPrefixes = tc.prefixes
					}
				})
				if res.Method != sqliteread.ReadInPlace {
					t.Errorf("method = %q, want the in-place fast path", res.Method)
				}
				if !slices.EqualFunc(res.Rows, tc.want, func(a, b sqliteread.Row) bool {
					return a.Key == b.Key && string(a.Value) == string(b.Value)
				}) {
					t.Errorf("rows = %q, want %q", res.Rows, tc.want)
				}
			}

			// An in-place read must not create -wal or -shm sidecars: the compensating control for this package's write-path lint exemption.
			if after := listDir(t, dir); !slices.Equal(after, before) {
				t.Errorf("a read changed the source directory:\n before %v\n after  %v", before, after)
			}
		})
	}
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
	for _, want := range []string{"cursorAuth/stripeMembershipType", "cursorAuth/cachedEmail",
		"cursorAuth/cachedSignUpType", "cursorAuth/cachedTeam"} {
		if _, ok := got[want]; !ok {
			t.Errorf("allowed key %s did not survive", want)
		}
	}
	for k, v := range got {
		if strings.Contains(v, token) {
			t.Errorf("a token survived under %s", k)
		}
	}
	if len(got) != 4 {
		t.Errorf("want exactly the 4 allowed keys, got %d: %v", len(got), got)
	}
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

	for _, r := range res.Rows {
		if strings.Contains(strings.ToLower(r.Key), "cursorauth") {
			t.Errorf("an auth key survived the filter: %s", r.Key)
		}
		if strings.Contains(string(r.Value), token) {
			t.Errorf("the token survived in %s: %s", r.Key, r.Value)
		}
		if strings.Contains(string(r.Value), "EncryptionKey") {
			t.Errorf("an encryption-key field survived in %s", r.Key)
		}
	}
	if res.DeniedKeys == 0 {
		t.Error("no keys were reported denied, so the filter's operation is invisible")
	}
	if res.StrippedFields == 0 {
		t.Error("no fields were reported stripped")
	}

	// The rest of the row has to survive: dropping the whole composerData row would take the conversation with it.
	found := false
	for _, r := range res.Rows {
		if r.Key == "composerData:c1" {
			found = true
			var m map[string]any
			if err := json.Unmarshal(r.Value, &m); err != nil {
				t.Fatalf("the stripped row is no longer JSON: %v", err)
			}
			if m["composerId"] != "c1" {
				t.Error("stripping removed the fields the join needs")
			}
			if m["fullConversationHeadersOnly"] == nil {
				t.Error("stripping removed the bubble ordering")
			}
		}
	}
	if !found {
		t.Error("the composerData row was dropped entirely")
	}
}

// Unreadable by every method must be reported as a failure, not as an empty successful read.
func TestAnUnreadableDatabaseFailsEveryMethod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	for _, tc := range []struct {
		name string
		now  func() time.Time
		want string
	}{
		{name: "the error names every method", want: "every read method failed"},
		// The raw copy is cold-only and must refuse here: a raw copy of a database being written is not consistent.
		{name: "a live database is not copied raw", now: time.Now, want: "not cold enough"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
			if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			scratch := filepath.Join(t.TempDir(), "scratch")

			inPlace := read(t, path, func(o *sqliteread.Options) { o.ScratchDir = scratch })
			if inPlace.Method != sqliteread.ReadInPlace {
				t.Fatalf("expected the fast path first, got %q", inPlace.Method)
			}

			// Force a fallback by making the source unreadable.
			if err := os.Chmod(path, 0o000); err != nil {
				t.Skipf("cannot chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

			_, err := sqliteread.Read(sqliteread.Options{
				Path:        path,
				ScratchDir:  scratch,
				Table:       "cursorDiskKV",
				KeyPrefixes: []string{"composerData:"},
				Now:         tc.now,
			})
			if err == nil {
				t.Fatal("an unreadable database produced a successful read")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not contain %q: %v", tc.want, err)
			}
		})
	}
}

// THE FALLBACK-EQUIVALENCE GATE: every read method returns identical ROW VALUES, which is why hashes come from values and not bytes.
func TestEveryReadMethodReturnsIdenticalRowsAndCleansUp(t *testing.T) {
	path := newStore(t, map[string]string{
		"composerData:c1": `{"composerId":"c1","fullConversationHeadersOnly":[{"bubbleId":"b1","type":1}]}`,
		"bubbleId:c1:b1":  `{"type":1,"text":"hello","createdAt":"2026-07-30T10:00:00Z"}`,
		"bubbleId:c1:b2":  `{"type":2,"text":"world","createdAt":"2026-07-30T10:00:01Z"}`,
	})
	// Old enough for the cold copy to accept it.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	before := listDir(t, dir)

	methods := []sqliteread.ReadMethod{
		sqliteread.ReadInPlace,
		sqliteread.ReadSnapshot,
		sqliteread.ReadColdCopy,
	}
	var reference []sqliteread.Row

	for _, want := range methods {
		// Pre-create what a crash mid-VACUUM leaves: resuming into it would query a corrupt partial database.
		scratch := filepath.Join(t.TempDir(), "scratch")
		if err := os.MkdirAll(scratch, 0o700); err != nil {
			t.Fatal(err)
		}
		leftover := filepath.Join(scratch, "snapshot-state.vscdb.sqlite")
		if err := os.WriteFile(leftover, []byte("corrupt partial"), 0o600); err != nil {
			t.Fatal(err)
		}

		res, err := sqliteread.Read(sqliteread.Options{
			Path:        path,
			ScratchDir:  scratch,
			Table:       "cursorDiskKV",
			KeyPrefixes: []string{"composerData:", "bubbleId:"},
			StartAt:     want,
		})
		if err != nil {
			t.Fatalf("method %s: %v", want, err)
		}
		if res.Method != want {
			t.Fatalf("asked for method %s, got %s", want, res.Method)
		}
		if after := listDir(t, dir); !slices.Equal(after, before) {
			t.Errorf("method %s changed the source directory:\n before %v\n after  %v", want, before, after)
		}
		// The snapshot read replaces the leftover and then deletes its own copy; the other methods leave the slot alone and add nothing.
		left := listDir(t, scratch)
		if want == sqliteread.ReadSnapshot {
			if len(left) != 0 {
				t.Errorf("the scratch directory still holds %v", left)
			}
		} else if !slices.Equal(left, []string{"snapshot-state.vscdb.sqlite"}) {
			t.Errorf("method %s left %v in the scratch directory", want, left)
		}

		if reference == nil {
			if len(res.Rows) != 3 {
				t.Fatalf("method %s read %d rows, want 3", want, len(res.Rows))
			}
			reference = res.Rows
			continue
		}
		if len(res.Rows) != len(reference) {
			t.Fatalf("method %s returned %d rows, method %s returned %d",
				want, len(res.Rows), methods[0], len(reference))
		}
		for i := range res.Rows {
			if res.Rows[i].Key != reference[i].Key {
				t.Errorf("method %s row %d key = %s, want %s", want, i, res.Rows[i].Key, reference[i].Key)
			}
			if string(res.Rows[i].Value) != string(reference[i].Value) {
				t.Errorf("method %s row %s value differs from the in-place read", want, res.Rows[i].Key)
			}
		}
	}
}

// THE SIDECAR BASENAME RULE. A mistake this project already made once.
func TestAColdCopyKeepsSidecarBasenames(t *testing.T) {
	src := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
	// Give it a WAL and an SHM, as a live database has.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(src+suffix, []byte("sidecar"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	dst := t.TempDir()
	copied, err := sqliteread.CopyCold(src, dst)
	if err != nil {
		t.Fatal(err)
	}

	// A copy that omits or RENAMES the -wal opens without the WAL's contents, since SQLite finds the sidecar by basename.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		want := copied + suffix
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s did not land beside the copy: %v", filepath.Base(want), err)
		}
	}
	if filepath.Base(copied) != filepath.Base(src) {
		t.Errorf("the copy was renamed: %s vs %s", filepath.Base(copied), filepath.Base(src))
	}
}

func TestAColdCopyRefusesToOverwriteAnExistingTarget(t *testing.T) {
	src := newStore(t, map[string]string{"composerData:c1": `{"composerId":"c1"}`})
	dst := t.TempDir()

	if _, err := sqliteread.CopyCold(src, dst); err != nil {
		t.Fatal(err)
	}
	// Second copy into the same directory: overwriting could mix a fresh database with a stale -wal.
	if _, err := sqliteread.CopyCold(src, dst); err == nil {
		t.Fatal("a cold copy overwrote an existing target")
	}
}

func TestAnUndeclaredTableIsRefused(t *testing.T) {
	path := newStore(t, map[string]string{"composerData:c1": `{}`})
	_, err := sqliteread.Read(sqliteread.Options{
		Path:       path,
		ScratchDir: t.TempDir(),
	})
	// Scope is declared: a read with no table is a programming fault, not something to guess at.
	if err == nil {
		t.Fatal("a read with no declared table was accepted")
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
