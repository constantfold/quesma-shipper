package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// The failure the checksum exists for: a source_hash flipped in place still parses, still
// satisfies the schema, and reads as a completed ship. Trusting it loses that file forever.
func TestAnInPlaceCorruptionIsCaughtByTheChecksum(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()

	path := filepath.Join(dir, engine.FileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	tampered := strings.Replace(string(raw), sha, otherSha, 1)
	require.NotEqual(t, string(raw), tampered, "could not tamper with the source hash; document shape changed")
	require.NoError(t, os.WriteFile(path, []byte(tampered), 0o600))

	if _, err := engine.Peek(dir); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("the tampered document was trusted: %v", err)
	}
}

// A document from before the field existed has no checksum and must still load; it earns one on
// the next rewrite rather than being treated as corrupt.
func TestADocumentWithoutAChecksumStillLoads(t *testing.T) {
	dir := t.TempDir()
	doc := `{"state_schema": 1, "entries": []}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte(doc), 0o600))
	if _, err := engine.Peek(dir); err != nil {
		t.Fatalf("a pre-checksum document must load: %v", err)
	}

	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	s.Close()
	raw, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"checksum"`, "the rewrite should have stamped a checksum")
}

// An unknown field is ignored and dropped on the next rewrite; absence fails toward re-shipping.
func TestUnknownFieldIsIgnored(t *testing.T) {
	dir := t.TempDir()
	doc := `{"state_schema": 1, "entries": [], "pending_uploads": []}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte(doc), 0o600))
	s, err := engine.Open(dir, installID)
	require.NoErrorf(t, err, "a document with an unknown field must still load: %v", err)
	s.Close()
}

// The one exception to load's interpret-don't-audit stance: a negative attempts count reaches the
// backoff as a negative shift and panics, so the document is refused with the entry named.
func TestNegativeAttemptsIsRejectedOnLoad(t *testing.T) {
	dir := t.TempDir()
	doc := `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts", "native_path": "/x/a.jsonl", "attempts": -5}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte(doc), 0o600))
	_, err := engine.Peek(dir)
	require.Error(t, err, "a negative attempts count must be rejected")
	assert.Truef(t, strings.Contains(err.Error(), "attempts") && strings.Contains(err.Error(), "/x/a.jsonl"), "the error must name the value and the entry, got: %v", err)
}

// Load interprets, it does not audit. A missing field comes back zero, which matches no file, so
// the engine re-reads and re-ships onto the same key: the safe direction to fail in.
func TestMissingFieldsLoadAsZeroValues(t *testing.T) {
	dir := t.TempDir()
	doc := `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts", "native_path": "/x/a.jsonl"}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte(doc), 0o600))

	loaded, err := engine.Peek(dir)
	require.NoErrorf(t, err, "a well-formed document must load: %v", err)
	k := engine.Key{SourceID: "claude-code-transcripts", NativePath: "/x/a.jsonl"}
	fp, ok := loaded.Entries[k]
	if !ok {
		t.Fatalf("entry missing; document loaded as %+v", loaded.Entries)
	}
	assert.Truef(t, fp.SourceHash == "" && fp.SourceSize == 0 && fp.SourceMTime.IsZero(), "absent fields must read back zero, got %+v", fp)
}

// A document carrying the retired sink_etag must load and simply drop the field: the schema is
// not bumped for a removal, and refusing would re-ship the install's whole history.
func TestALegacySinkETagLoadsAndIsDropped(t *testing.T) {
	dir := t.TempDir()
	doc := `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts", ` +
		`"native_path": "/x/a.jsonl", "source_hash": "` + sha + `", "sink_etag": "abc123"}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, engine.FileName), []byte(doc), 0o600))

	loaded, err := engine.Peek(dir)
	require.NoErrorf(t, err, "a document carrying sink_etag must still load: %v", err)
	k := engine.Key{SourceID: "claude-code-transcripts", NativePath: "/x/a.jsonl"}
	fp, ok := loaded.Entries[k]
	if !ok {
		t.Fatalf("entry missing; document loaded as %+v", loaded.Entries)
	}
	assert.Equalf(t, sha, fp.SourceHash, "the entry beside the dropped field was lost: %+v", fp)

	// The rewrite drops it: the schema refuses unknown properties on the way out.
	s := open(t, dir)
	require.NoError(t, commit(s, k, fingerprint()))
	raw, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.NotContainsf(t, string(raw), "sink_etag", "sink_etag survived a rewrite:\n%s", raw)
}

// The schema is enforced on the way out, so a bad commit fails and the old document stays.
func TestCommitOfAnUnserializableEntryFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	before, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)

	bad := engine.Key{
		SourceID:   "claude-code-transcripts",
		NativePath: "",
	}
	require.Error(t, commit(s, bad, fingerprint()), "a document that would not satisfy its own schema must not be written")

	after, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.Equal(t, string(after), string(before), "the rejected commit reached the disk")
}

// A derived entry carries the enricher that produced it and its output hash.
func TestDerivedEntryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)

	k := engine.Key{
		SourceID:   "cursor-transcripts",
		NativePath: "/c/c8cbeb0b.jsonl.enriched.jsonl",
	}
	fp := fingerprint()
	fp.Enricher = &engine.EnricherRef{ID: "cursor-transcript-join", Version: 1}
	fp.OutputHash = otherSha
	require.NoError(t, commit(s, k, fp))
	s.Close()

	s2 := open(t, dir)
	got, ok := s2.Get(k)
	require.True(t, ok, "derived entry missing after reload")
	assert.Truef(t, got.Enricher != nil && got.Enricher.ID == "cursor-transcript-join" && got.Enricher.Version == 1, "enricher ref: %+v", got.Enricher)
	assert.Equalf(t, otherSha, got.OutputHash, "output hash: %q", got.OutputHash)
}
