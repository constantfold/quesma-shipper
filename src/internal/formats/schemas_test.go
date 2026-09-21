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
		if _, err := formats.Compile(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	entries, err := fs.Glob(formats.FS, "*.schema.json")
	require.NoError(t, err)
	assert.Lenf(t, entries, len(formats.All), "embedded schemas %v, All lists %v — keep them in step", entries, formats.All)
}

func decode(t *testing.T, doc string) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(doc)))
	require.NoErrorf(t, err, "test document is not valid JSON: %v", err)
	return v
}

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const anotherSha = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"

// --- fingerprint state ------------------------------------------------------

func TestFingerprintStateMinimal(t *testing.T) {
	doc := `{"state_schema": 1, "entries": []}`
	require.NoError(t, formats.Validate(formats.FingerprintState, decode(t, doc)))
}

func TestFingerprintStateFull(t *testing.T) {
	doc := `{
	  "state_schema": 1,
	  "install_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
	  "updated_at": "2026-07-30T10:00:00Z",
	  "source_specs": {"claude-code-transcripts": "` + sha + `"},
	  "entries": [{
	    "source_id": "claude-code-transcripts",
	    "native_path": "/Users/__USER__/.claude/projects/proj/a.jsonl",
	    "source_size": 4096,
	    "source_mtime": "2026-07-30T09:59:00Z",
	    "source_hash": "` + sha + `",
	    "sink_etag": "\"abc123\"",
	    "enricher": {"id": "cursor-transcript-join", "version": 1},
	    "output_hash": "` + sha + `",
	    "parked": false,
	    "last_error": "",
	    "backoff_until": "2026-07-30T11:00:00Z"
	  }]
	}`
	require.NoError(t, formats.Validate(formats.FingerprintState, decode(t, doc)))
}

// An unknown state_schema means downgrade or corruption, refused rather than guessed at.
func TestFingerprintStateRejectsForeignSchemaVersion(t *testing.T) {
	doc := `{"state_schema": 2, "entries": []}`
	require.Error(t, formats.Validate(formats.FingerprintState, decode(t, doc)), "state_schema 2 must be rejected, never guessed at")
}

func TestFingerprintStateRejectsUnknownField(t *testing.T) {
	doc := `{"state_schema": 1, "entries": [], "pending_uploads": []}`
	require.Error(t, formats.Validate(formats.FingerprintState, decode(t, doc)), "unknown top-level fields must be rejected")
}

// The entry key is (source_id, native_path). A path-less entry keys on nothing.
func TestFingerprintStateRequiresFullKey(t *testing.T) {
	doc := `{"state_schema": 1, "entries": [{
	  "source_id": "claude-code-transcripts"
	}]}`
	require.Error(t, formats.Validate(formats.FingerprintState, decode(t, doc)), "an entry without native_path must be rejected")
}

func TestFingerprintStateRejectsNonSHA256Hash(t *testing.T) {
	doc := `{"state_schema": 1, "entries": [{
	  "source_id": "s",
	  "native_path": "/x/a.jsonl",
	  "source_hash": "deadbeef"
	}]}`
	require.Error(t, formats.Validate(formats.FingerprintState, decode(t, doc)), "a truncated or non-hex hash must be rejected")
}

// --- manifest ---------------------------------------------------------------

func minimalManifest() string {
	return `{
	  "manifest_version": 1,
	  "organization_id": "default",
	  "install_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
	  "source_id": "claude-code-transcripts",
	  "native_path": "/Users/__USER__/.claude/projects/proj/a.jsonl",
	  "gather": "file_glob",
	  "artifact_class": "trajectory",
	  "source_hash": "` + sha + `",
	  "shipped_hash": "` + anotherSha + `",
	  "payload_size": 4096,
	  "sealed_at": "2026-07-30T10:00:00Z",
	  "client": {"version": "0.1.0", "os": "darwin", "arch": "arm64"}
	}`
}

func TestManifestMinimal(t *testing.T) {
	require.NoError(t, formats.Validate(formats.Manifest, decode(t, minimalManifest())))
}

// source_hash is the pre-redaction identity, shipped_hash the post-redaction check; both required.
func TestManifestRequiresBothHashes(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(minimalManifest()), &doc))
	for _, missing := range []string{"source_hash", "shipped_hash"} {
		t.Run(missing, func(t *testing.T) {
			clone := map[string]any{}
			for k, v := range doc {
				if k != missing {
					clone[k] = v
				}
			}
			b, err := json.Marshal(clone)
			require.NoError(t, err)
			require.Error(t, formats.Validate(formats.Manifest, decode(t, string(b))))
		})
	}
}

// A derived object without provenance is unverifiable, and it is the only carrier of DB fields.
func TestManifestDerivedRequiresProvenance(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(minimalManifest()), &doc))
	doc["derived"] = true
	b, _ := json.Marshal(doc)
	require.Error(t, formats.Validate(formats.Manifest, decode(t, string(b))), "derived: true without enricher/derived_from/enrich_status must be rejected")

	doc["enricher"] = map[string]any{"id": "cursor-transcript-join", "version": 1}
	doc["derived_from"] = []string{sha}
	doc["enrich_status"] = "ok"
	doc["db_provenance"] = map[string]any{
		"db_path":     "/Users/__USER__/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
		"read_method": "scratch_snapshot",
		"keyspaces":   []string{"composerData", "bubbleId"},
		"rows_read":   148,
	}
	b, _ = json.Marshal(doc)
	require.NoError(t, formats.Validate(formats.Manifest, decode(t, string(b))))
}

// Rule-id and count granularity only: byte ranges would locate and size each redacted secret.
func TestManifestRedactionSummaryRejectsByteRanges(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(minimalManifest()), &doc))
	doc["redaction"] = map[string]any{
		"density":   0.012,
		"rule_hits": map[string]int{"aws-secret-key": 4, "email": 2},
		"scan_mode": "decoded_json_values",
	}
	b, _ := json.Marshal(doc)
	require.NoError(t, formats.Validate(formats.Manifest, decode(t, string(b))))

	doc["redaction"] = map[string]any{
		"density": 0.012,
		"spans":   []any{map[string]int{"offset": 128, "length": 40}},
	}
	b, _ = json.Marshal(doc)
	require.Error(t, formats.Validate(formats.Manifest, decode(t, string(b))), "byte-range spans in a redaction summary must be rejected")
}

func TestManifestShapeSniffIsAClosedEnum(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(minimalManifest()), &doc))
	for _, v := range []string{"ok", "empty", "unexpected_shape", "unreadable"} {
		doc["shape_sniff"] = v
		b, _ := json.Marshal(doc)
		assert.NoError(t, formats.Validate(formats.Manifest, decode(t, string(b))))
	}
	doc["shape_sniff"] = "probably_fine"
	b, _ := json.Marshal(doc)
	require.Error(t, formats.Validate(formats.Manifest, decode(t, string(b))), "shape_sniff must be a closed enum (pin 11)")
}

// A retired container's fields must not reappear by accident.
func TestManifestRejectsBundleFields(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(minimalManifest()), &doc))
	for _, field := range []string{"prev_bundle_hash", "bundle_content_id", "entries"} {
		clone := map[string]any{}
		for k, v := range doc {
			clone[k] = v
		}
		clone[field] = "x"
		b, _ := json.Marshal(clone)
		assert.Error(t, formats.Validate(formats.Manifest, decode(t, string(b))))
	}
}
