package engine_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

// A raw + derived pair through the real loop: the derived object is scrubbed and sealed, and no SQLite row ships.

const enrichConv = "5d1f7b3e-9a2c-4e8f-b1d0-3c4a5b6c7d8e"

// cursorTranscript is the raw side, in the shape the survey found exhaustive.
const cursorTranscript = `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nlist the workspace\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Listing the workspace folder contents."},{"type":"tool_use","name":"Shell","input":{"command":"ls -la /work/api"}}]}}
{"type":"turn_ended","status":"success"}
`

// Markers that must never appear in any object; all three are planted in the fixture database.
const (
	unusedRowMarker = "UNUSED_STORE_FIELD_MUST_NOT_SHIP"
	sessionToken    = "CURSOR-SESSION-TOKEN-MUST-NOT-SHIP"
	blobKey         = "BLOB-ENCRYPTION-KEY-MUST-NOT-SHIP"
)

// cursorFixture writes a Cursor-shaped store and transcript into the fixture's home.
func cursorFixture(t *testing.T, f *fixture) (dbPath string) {
	t.Helper()

	// The transcript, where the catalog's globs will find it.
	dir := filepath.Join(f.home, ".cursor", "projects", "api", "agent-transcripts")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, enrichConv+".jsonl"), []byte(cursorTranscript), 0o600))

	// The store, with auth material and unused fields planted in it.
	dbPath = filepath.Join(f.home, "globalStorage", "state.vscdb")
	require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0o700))
	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);
		CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`)
	require.NoError(t, err)

	rows := []struct{ table, key, value string }{
		{"ItemTable", "cursorAuth/accessToken", sessionToken},
		{"cursorDiskKV", "cursorAuth/refreshToken", sessionToken},
		{
			"cursorDiskKV", "composerData:" + enrichConv,
			fmt.Sprintf(`{"composerId":%q,"blobEncryptionKey":%q,"%s":"x",
				"fullConversationHeadersOnly":[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]}`,
				enrichConv, blobKey, unusedRowMarker),
		},
		{"cursorDiskKV", "bubbleId:" + enrichConv + ":b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`},
		{"cursorDiskKV", "bubbleId:" + enrichConv + ":b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`},
		{
			"cursorDiskKV", "bubbleId:" + enrichConv + ":b3",
			toolResult("total 24\n-rw-r--r-- 1 jane staff 812 main.go"),
		},
		// A checkpoint row, outside the declared keyspaces entirely.
		{"cursorDiskKV", "checkpointId:" + enrichConv + ":x", `{"` + unusedRowMarker + `":"y"}`},
	}
	for _, r := range rows {
		_, err := db.Exec(`INSERT INTO `+r.table+` (key, value) VALUES (?, ?)`, r.key, r.value)
		require.NoError(t, err, r.key)
	}
	return dbPath
}

// enrichOpts builds engine options with the enricher registry wired at the fixture's database.
func enrichOpts(t *testing.T, f *fixture, dbPath string, enricherOn bool) engine.Options {
	t.Helper()
	o := f.opts()
	o.Sources = []sources.Resolved{{
		Source: sources.Source{
			ID:            "cursor-transcripts",
			Family:        "cursor",
			Gather:        "file_glob",
			ArtifactClass: "trajectory",
			Include:       []string{"**/agent-transcripts/**/*.jsonl"},
			Enrichers:     map[string]bool{"cursor-transcript-join": enricherOn},
			Sniff:         &sources.Sniff{Kind: "jsonl", MaxScanBytes: 65536},
		},
		Root:            filepath.Join(f.home, ".cursor", "projects"),
		Enabled:         true,
		SpecFingerprint: strings.Repeat("c", 64),
	}}
	o.Enrichers = transforms.NewRegistry(&fixtureEnricher{Enricher: cursorjoin.New(), db: dbPath})
	env, err := sources.OSEnv()
	require.NoError(t, err)
	o.Env = env
	return o
}

// fixtureEnricher overrides only the database location; the join and its filter stay the shipping code.
type fixtureEnricher struct {
	*cursorjoin.Enricher
	db string
}

func (f *fixtureEnricher) DBCandidates() []string { return []string{f.db} }

// A raw/derived pair preserves its provenance while excluding database rows and credentials.
func TestEnrichedPairContract(t *testing.T) {
	const planted = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
	for _, tc := range []struct{ name, result string }{
		{"original store", ""},
		{"secret in database tool result", "exported GITHUB_TOKEN=" + planted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			db := cursorFixture(t, f)
			if tc.result != "" {
				updateBubble(t, db, "bubbleId:"+enrichConv+":b3", toolResult(tc.result))
			}
			// Preview covers the derived object too, being the one built from a database, and uploads nothing.
			preview := f.run(func(o *engine.Options) { *o = enrichOpts(t, f, db, true); o.DryRun = true })
			require.Empty(t, f.port.keys(), "preview uploaded something")
			require.Len(t, preview.Sources[0].Files, 2)
			assert.True(t, strings.HasSuffix(preview.Sources[0].Files[1].NativePath, ".enriched.jsonl"), "preview did not report the derived object")

			rep := f.runWith(enrichOpts(t, f, db, true))
			require.Equal(t, 2, rep.Shipped, "raw and derived must both ship")
			require.Len(t, f.port.keys(), 2, "raw and derived must have distinct keys")
			f.port.storedOnce(t)
			assert.Len(t, f.port.sizes(), 2, "raw and derived each authorize their own group")

			var rawManifest, derivedManifest transforms.Manifest
			for _, k := range f.port.keys() {
				obj, m, payload := f.openObject(t, k)
				for _, secret := range []string{sessionToken, blobKey, unusedRowMarker, planted} {
					assert.NotContains(t, string(obj.Body), secret, "%s ciphertext", k)
					assert.NotContains(t, string(payload), secret, "%s payload", k)
					for name, value := range obj.Metadata {
						assert.NotContains(t, value, secret, "%s metadata %s", k, name)
					}
				}
				assert.NotEqual(t, "sqlite_rows", m.Gather, k)
				assert.NotContains(t, m.NativePath, "state.vscdb", k)
				if m.Derived {
					derivedManifest = m
					assert.Equal(t, "true", obj.Metadata["derived"], k)
					assert.NotEmpty(t, obj.Metadata["artifact-class"], k)
				} else {
					rawManifest = m
					assert.Empty(t, obj.Metadata["derived"], k)
				}
			}
			require.NotEqual(t, "", rawManifest.SourceHash, "no raw object shipped")
			require.True(t, derivedManifest.Derived, "no derived object shipped")

			// derived_from carries the raw object's source hash, the only link downstream can verify.
			assert.Equal(t, []string{rawManifest.SourceHash}, derivedManifest.DerivedFrom)
			assert.Truef(t, derivedManifest.Enricher != nil && derivedManifest.Enricher.ID == "cursor-transcript-join" && derivedManifest.Enricher.Version == 4, "enricher = %+v", derivedManifest.Enricher)
			assert.Equalf(t, string(transforms.StatusOK), derivedManifest.EnrichStatus, "enrich_status = %q", derivedManifest.EnrichStatus)

			// The rows never ship, so DB provenance is the only account of where the fields came from.
			p := derivedManifest.DBProvenance
			require.Truef(t, p != nil && p.ReadMethod != "" && p.RowsRead != 0 && len(p.Keyspaces) != 0, "db_provenance is incomplete: %+v", p)
			assert.Containsf(t, p.DBPath, "state.vscdb", "db_provenance path = %q", p.DBPath)
			// A real path on someone's machine, so the username placeholder applies here too.
			assert.NotContainsf(t, p.DBPath, "/Users/"+os.Getenv("USER")+"/", "db_provenance leaks the username: %q", p.DBPath)
		})
	}
}

// Recent transcripts are re-read for enrichment; only changed derived output uploads, onto the same key.
func TestTheDerivedObjectReShipsOnlyWhenItsOutputChanges(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)
	first := f.runWith(enrichOpts(t, f, db, true))
	require.Equal(t, 2, first.Shipped)
	keys := f.port.keys()

	f.reopen()
	second := f.runWith(enrichOpts(t, f, db, true))
	assert.Zero(t, second.Shipped)
	assert.ElementsMatch(t, keys, f.port.keys())

	for _, result := range []string{"A LATE RESULT ARRIVED", "LATE"} {
		// Only the database changes: size/mtime filtering must still read the recent transcript.
		updateBubble(t, db, "bubbleId:"+enrichConv+":b3", toolResult(result))
		f.reopen()
		rep := f.runWith(enrichOpts(t, f, db, true))
		require.Equal(t, 1, rep.Shipped, "only the derived revision may ship")
		assert.ElementsMatch(t, keys, f.port.keys())
		found := false
		for _, k := range f.port.keys() {
			_, m, payload := f.openObject(t, k)
			found = found || (m.Derived && strings.Contains(string(payload), fmt.Sprintf(`"result":%q`, result)))
		}
		assert.True(t, found, "late result %q never reached the sink", result)
	}
}

// Whatever the enricher does, exactly the raw object ships; only a mismatch, not a missing database, raises the alarm.
func TestRawShipsAloneWhenThereIsNoJoin(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enricherOn bool
		mismatch   bool
	}{
		{"disabled", false, false},
		{"mismatch", true, true},
		{"no database", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			db := cursorFixture(t, f)
			if tc.mismatch {
				// Divergence mid-stream, as vendor drift would; after the last matched event it is a tail.
				updateBubble(t, db, "bubbleId:"+enrichConv+":b2",
					`{"bubbleId":"b2","type":2,"text":"a completely different sentence about nothing"}`)
			} else if tc.enricherOn {
				db = filepath.Join(f.home, "nope", "state.vscdb")
			}
			rep := f.runWith(enrichOpts(t, f, db, tc.enricherOn))
			require.Equalf(t, 1, rep.Shipped, "shipped %d, want the raw object only: %+v", rep.Shipped, rep.Sources)
			keys := f.port.keys()
			require.Len(t, keys, 1)
			_, m, _ := f.openObject(t, keys[0])
			assert.False(t, m.Derived, "no join still shipped a derived object")
			assert.Equal(t, transforms.Hash([]byte(cursorTranscript)), m.SourceHash, "the raw object's bytes changed")
			assert.Equal(t, enrichConv+".jsonl", filepath.Base(m.NativePath))

			src := rep.Sources[0]
			assert.Equal(t, tc.mismatch, rep.EnrichMismatch != 0, "run-level mismatch counter %d", rep.EnrichMismatch)
			assert.Equal(t, tc.mismatch, src.EnrichMismatch != 0, "per-source mismatch counter %d", src.EnrichMismatch)
			if tc.mismatch {
				assert.NotEmpty(t, src.EnrichNotes, "no note explains the mismatch")
			}
		})
	}
}

func toolResult(result string) string {
	return fmt.Sprintf(`{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
		"name":"run_terminal_cmd","status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}",
		"result":%q}}`, result)
}

func updateBubble(t *testing.T, dbPath, key, value string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err)
	defer db.Close()
	_, execErr := db.Exec(`UPDATE cursorDiskKV SET value = ? WHERE key = ?`, value, key)
	require.NoError(t, execErr)
	// Touch the file so a coldness check cannot mistake it for stale.
	require.NoError(t, os.Chtimes(dbPath, time.Now(), time.Now()))
}
