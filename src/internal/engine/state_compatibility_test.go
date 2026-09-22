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

// Historical and partially populated documents load safely, then rewrite into the current shape.
func TestCompatibleDocumentsLoadAndRewrite(t *testing.T) {
	k := key("/x/a.jsonl")
	for _, tc := range []struct {
		name, document string
		entries        map[engine.Key]engine.Fingerprint
	}{
		{"pre-checksum", `{"state_schema": 1, "entries": []}`, map[engine.Key]engine.Fingerprint{}},
		{"unknown field", `{"state_schema": 1, "entries": [], "pending_uploads": []}`, map[engine.Key]engine.Fingerprint{}},
		{"missing fields", `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts", "native_path": "/x/a.jsonl"}]}`,
			map[engine.Key]engine.Fingerprint{k: {}}},
		{"legacy sink etag", `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts", ` +
			`"native_path": "/x/a.jsonl", "source_hash": "` + sha + `", "sink_etag": "abc123"}]}`,
			map[engine.Key]engine.Fingerprint{k: {SourceHash: sha}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, engine.FileName)
			require.NoError(t, os.WriteFile(path, []byte(tc.document), 0o600))
			doc, err := engine.Peek(dir)
			require.NoError(t, err)
			assert.Equal(t, tc.entries, doc.Entries)

			s := open(t, dir)
			assert.False(t, s.Corrupt(), "compatibility must not depend on discarding the document")
			require.NoError(t, commit(s, k, fingerprint()))
			require.NoError(t, s.Close())
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Contains(t, string(raw), `"checksum"`)
			assert.NotContains(t, string(raw), "pending_uploads")
			assert.NotContains(t, string(raw), "sink_etag")
		})
	}
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

// The schema is enforced on the way out, so a bad commit fails and the old document stays.
func TestCommitOfAnUnserializableEntryFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	require.NoError(t, commit(s, key("/x/a.jsonl"), fingerprint()))
	before, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)

	bad := engine.Key{SourceID: "claude-code-transcripts", NativePath: ""}
	require.Error(t, commit(s, bad, fingerprint()), "a document that would not satisfy its own schema must not be written")

	after, err := os.ReadFile(filepath.Join(dir, engine.FileName))
	require.NoError(t, err)
	assert.Equal(t, string(after), string(before), "the rejected commit reached the disk")
}

// A derived entry carries the enricher that produced it and its output hash.
func TestDerivedEntryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)

	k := engine.Key{SourceID: "cursor-transcripts", NativePath: "/c/c8cbeb0b.jsonl.enriched.jsonl"}
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
