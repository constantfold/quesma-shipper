package formats_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// Every embedded schema compiles and All matches what is embedded; otherwise it fails at runtime.
func TestAllCompile(t *testing.T) {
	for _, name := range formats.All {
		_, err := formats.Compile(name)
		assert.NoError(t, err, name)
	}
	entries, err := fs.Glob(formats.FS, "*.schema.json")
	require.NoError(t, err)
	assert.Len(t, entries, len(formats.All), "embedded schemas and All must stay in step")
}

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func validate(t *testing.T, schema, doc string) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(doc)))
	require.NoErrorf(t, err, "test document is not valid JSON: %s", doc)
	return formats.Validate(schema, v)
}

func TestFingerprintStateSchema(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		valid     bool
	}{
		{"minimal", `{"state_schema": 1, "entries": []}`, true},
		{"full", `{"state_schema": 1, "install_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "updated_at": "2026-07-30T10:00:00Z",
		  "source_specs": {"claude-code-transcripts": "` + sha + `"},
		  "entries": [{"source_id": "claude-code-transcripts", "native_path": "/Users/__USER__/.claude/projects/proj/a.jsonl",
		    "source_size": 4096, "source_mtime": "2026-07-30T09:59:00Z", "source_hash": "` + sha + `", "sink_etag": "\"abc123\"",
		    "enricher": {"id": "cursor-transcript-join", "version": 1}, "output_hash": "` + sha + `",
		    "parked": false, "last_error": "", "backoff_until": "2026-07-30T11:00:00Z"}]}`, true},
		// An unknown state_schema means downgrade or corruption, refused rather than guessed at.
		{"foreign schema version", `{"state_schema": 2, "entries": []}`, false},
		{"unknown field", `{"state_schema": 1, "entries": [], "pending_uploads": []}`, false},
		// The entry key is (source_id, native_path). A path-less entry keys on nothing.
		{"entry without native_path", `{"state_schema": 1, "entries": [{"source_id": "claude-code-transcripts"}]}`, false},
		{"non-sha256 hash", `{"state_schema": 1, "entries": [{"source_id": "s", "native_path": "/x/a.jsonl", "source_hash": "deadbeef"}]}`, false},
	} {
		assert.Equal(t, tc.valid, validate(t, formats.FingerprintState, tc.doc) == nil, tc.name)
	}
}

// manifest returns the minimal valid manifest after edit has changed it.
func manifest(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	doc := map[string]any{
		"manifest_version": 1, "organization_id": "default", "install_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		"source_id": "claude-code-transcripts", "native_path": "/Users/__USER__/.claude/projects/proj/a.jsonl",
		"gather": "file_glob", "artifact_class": "trajectory", "source_hash": sha,
		"shipped_hash": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		"payload_size": 4096, "sealed_at": "2026-07-30T10:00:00Z",
		"client": map[string]any{"version": "0.1.0", "os": "darwin", "arch": "arm64"},
	}
	edit(doc)
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return string(b)
}

func set(key string, value any) func(map[string]any) {
	return func(doc map[string]any) { doc[key] = value }
}

func TestManifestSchema(t *testing.T) {
	provenance := func(doc map[string]any) {
		doc["derived"] = true
		doc["enricher"] = map[string]any{"id": "cursor-transcript-join", "version": 1}
		doc["derived_from"] = []string{sha}
		doc["enrich_status"] = "ok"
		doc["db_provenance"] = map[string]any{
			"db_path":     "/Users/__USER__/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
			"read_method": "scratch_snapshot", "keyspaces": []string{"composerData", "bubbleId"}, "rows_read": 148,
		}
	}
	for _, tc := range []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{"minimal", func(map[string]any) {}, true},
		// source_hash is the pre-redaction identity, shipped_hash the post-redaction check; both required.
		{"no source_hash", func(doc map[string]any) { delete(doc, "source_hash") }, false},
		{"no shipped_hash", func(doc map[string]any) { delete(doc, "shipped_hash") }, false},
		// A derived object without provenance is unverifiable, and it is the only carrier of DB fields.
		{"derived without provenance", set("derived", true), false},
		{"derived with provenance", provenance, true},
		// Rule-id and count granularity only: byte ranges would locate and size each redacted secret.
		{"redaction summary", set("redaction", map[string]any{"density": 0.012,
			"rule_hits": map[string]int{"aws-secret-key": 4, "email": 2}, "scan_mode": "decoded_json_values"}), true},
		{"redaction byte ranges", set("redaction", map[string]any{"density": 0.012,
			"spans": []any{map[string]int{"offset": 128, "length": 40}}}), false},
		{"shape_sniff ok", set("shape_sniff", "ok"), true},
		{"shape_sniff empty", set("shape_sniff", "empty"), true},
		{"shape_sniff unexpected_shape", set("shape_sniff", "unexpected_shape"), true},
		{"shape_sniff unreadable", set("shape_sniff", "unreadable"), true},
		{"shape_sniff outside the enum", set("shape_sniff", "probably_fine"), false},
		// A retired container's fields must not reappear by accident.
		{"prev_bundle_hash", set("prev_bundle_hash", "x"), false},
		{"bundle_content_id", set("bundle_content_id", "x"), false},
		{"entries", set("entries", "x"), false},
	} {
		assert.Equal(t, tc.valid, validate(t, formats.Manifest, manifest(t, tc.edit)) == nil, tc.name)
	}
}
