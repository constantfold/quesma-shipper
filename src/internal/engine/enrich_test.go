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

// End-to-end gates: a raw + derived pair through the real loop, the derived object taking the
// same scrub/seal/send path, and the invariant that matters most: NO SQLite rows in the sink.

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
	for _, stmt := range []string{
		`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`,
		`CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}

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
		if _, err := db.Exec(`INSERT INTO `+r.table+` (key, value) VALUES (?, ?)`, r.key, r.value); err != nil {
			t.Fatalf("insert %s: %v", r.key, err)
		}
	}
	return dbPath
}

// cursorSource is the catalog source the enricher attaches to.
func cursorSource(f *fixture, enricherOn bool) sources.Resolved {
	return sources.Resolved{
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
	}
}

// enrichOpts builds engine options with the enricher registry wired at the fixture's database.
func enrichOpts(t *testing.T, f *fixture, dbPath string, enricherOn bool) engine.Options {
	t.Helper()
	o := f.opts()
	o.Plan.Sources = []sources.Resolved{cursorSource(f, enricherOn)}
	o.Enrichers = transforms.NewRegistry(&fixtureEnricher{Enricher: cursorjoin.New(), db: dbPath})
	env, err := sources.OSEnv()
	require.NoError(t, err)
	o.Env = env
	return o
}

// fixtureEnricher is the real join with only the database LOCATION overridden: the join, the read
// ladder and the compiled filter must stay the shipping code.
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

// THE DISABLED-ENRICHER GATE: byte-identical to a raw-only run.
func TestDisablingTheEnricherLeavesAByteIdenticalRawRun(t *testing.T) {
	withEnricher := newFixture(t)
	dbA := cursorFixture(t, withEnricher)
	withEnricher.runWith(enrichOpts(t, withEnricher, dbA, true))

	without := newFixture(t)
	dbB := cursorFixture(t, without)
	without.runWith(enrichOpts(t, without, dbB, false))

	// Disabling must change exactly one thing, the derived object, and leave raw collection alone.
	rawWith := rawManifests(t, withEnricher)
	rawWithout := rawManifests(t, without)

	require.Lenf(t, rawWithout, 1, "the disabled run shipped %d raw objects, want 1", len(rawWithout))
	require.Lenf(t, rawWith, 1, "the enriched run shipped %d raw objects, want 1", len(rawWith))
	assert.Equal(t, rawWithout[0].SourceHash, rawWith[0].SourceHash, "enabling the enricher changed the raw object's source hash")
	// Compared without the temp directory: the two runs have different homes.
	assert.Equal(t, filepath.Base(rawWithout[0].NativePath), filepath.Base(rawWith[0].NativePath), "enabling the enricher changed the raw object's path")

	// And no derived object at all when disabled.
	for _, k := range without.port.keys() {
		_, m, _ := without.openObject(t, k)
		assert.Truef(t, !m.Derived, "a disabled enricher still produced %s", k)
	}
}

// A mismatch: raw ships, no derived object, and the alarm reaches the report.
func TestAMismatchShipsRawOnlyAndRaisesTheAlarm(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)

	// Break the join the way vendor drift would, MID-stream: divergence after the last matched
	// event is tolerated as a tail rather than counted as drift.
	updateBubble(t, db, "bubbleId:"+enrichConv+":b2",
		`{"bubbleId":"b2","type":2,"text":"a completely different sentence about nothing"}`)

	rep := f.runWith(enrichOpts(t, f, db, true))

	// Raw ships regardless, which keeps a drifted join from becoming a collection outage.
	require.Equalf(t, 1, rep.Shipped, "shipped %d, want the raw object only: %+v", rep.Shipped, rep.Sources)
	for _, k := range f.port.keys() {
		_, m, _ := f.openObject(t, k)
		assert.Truef(t, !m.Derived, "a mismatched join still shipped a derived object: %s", k)
	}

	// The alarm must reach the report at both levels: a mismatch means data goes uncollected.
	assert.NotEqual(t, 0, rep.EnrichMismatch, "the run-level mismatch counter is zero")
	var src engine.SourceOutcome
	for _, s := range rep.Sources {
		if s.SourceID == "cursor-transcripts" {
			src = s
		}
	}
	assert.NotEqual(t, 0, src.EnrichMismatch, "the per-source mismatch counter is zero")
	assert.NotEqual(t, 0, len(src.EnrichNotes), "no note explains the mismatch")
}

// preview computes the derived object and uploads nothing.
func TestPreviewComputesTheDerivedObjectWithoutUploading(t *testing.T) {
	f := newFixture(t)
	db := cursorFixture(t, f)

	o := enrichOpts(t, f, db, true)
	o.DryRun = true
	rep := f.runWith(o)

	assert.Lenf(t, f.port.keys(), 0, "preview uploaded %v", f.port.keys())
	// Preview must cover the derived object too: it is the one built from a database.
	var derived bool
	for _, s := range rep.Sources {
		for _, fo := range s.Files {
			if strings.HasSuffix(fo.NativePath, ".enriched.jsonl") {
				derived = true
			}
		}
	}
	assert.True(t, derived, "preview did not report the derived object it would have shipped")
}

// A missing database is not an alarm.
func TestNoDatabaseShipsRawOnlyWithoutAnAlarm(t *testing.T) {
	f := newFixture(t)
	cursorFixture(t, f)

	rep := f.runWith(enrichOpts(t, f, filepath.Join(f.home, "nope", "state.vscdb"), true))
	require.Equalf(t, 1, rep.Shipped, "shipped %d, want the raw object only", rep.Shipped)
	// An install with no store has nothing to derive from; counting it would bury the real alarm.
	assert.Equalf(t, 0, rep.EnrichMismatch, "a missing database raised %d mismatches", rep.EnrichMismatch)
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
	if _, err := db.Exec(`UPDATE cursorDiskKV SET value = ? WHERE key = ?`, value, key); err != nil {
		t.Fatal(err)
	}
	// Touch the file so a coldness check cannot mistake it for stale.
	require.NoError(t, os.Chtimes(dbPath, time.Now(), time.Now()))
}

func rawManifests(t *testing.T, f *fixture) []transforms.Manifest {
	t.Helper()
	var out []transforms.Manifest
	for _, k := range f.port.keys() {
		_, m, _ := f.openObject(t, k)
		if !m.Derived {
			out = append(out, m)
		}
	}
	return out
}
