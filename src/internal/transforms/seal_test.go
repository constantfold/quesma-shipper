package transforms

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func identity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id
}

func manifest() Manifest {
	return Manifest{
		ManifestVersion: ManifestVersion,
		OrganizationID:  "default",
		InstallID:       "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		SourceID:        "claude-code-transcripts",
		NativePath:      "/Users/__USER__/.claude/projects/-Users-__USER__-work-api/s.jsonl",
		Gather:          "file_glob",
		ArtifactClass:   "trajectory",
		SourceHash:      strings.Repeat("a", 64),
		SealedAt:        "2026-07-30T10:00:00Z",
		ShapeSniff:      "ok",
		Client:          Client{Version: "0.1.0", OS: "darwin", Arch: "arm64"},
		RunID:           "0123456789abcdef",
	}
}

// Every input must preserve payload, provenance and the hashes exposed in plaintext metadata.
func TestSealOpenRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		client  Client
	}{
		{"jsonl", []byte("{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n"), manifest().Client},
		{"empty", nil, manifest().Client},
		{"metadata hash", []byte("{\"line\":\"one\"}\n"), manifest().Client},
		{"stamped build", []byte("{}\n"), Client{
			Version: "0.0.0-d5f735643cbd+dirty", Commit: "d5f735643cbd3c70f71d2ed52746be1cadfe3a15",
			Modified: true, GoVersion: "go1.25.0", OS: "linux", Arch: "amd64",
		}},
		{"unstamped build", []byte("{}\n"), Client{Version: "unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := identity(t)
			m := manifest()
			m.Client = tc.client
			obj, sealed, err := Seal(m, tc.payload, []age.Recipient{id.Recipient()})
			require.NoError(t, err)
			got, payload, err := Open(obj, id)
			require.NoError(t, err)
			assert.Equal(t, string(tc.payload), string(payload))
			assert.Equal(t, m.NativePath, got.NativePath)
			assert.Equal(t, m.RunID, got.RunID)
			assert.Equal(t, m.Client, got.Client)
			assert.Equal(t, int64(len(tc.payload)), got.PayloadSize)
			assert.Equal(t, sha256Hex(tc.payload), got.ShippedHash)
			assert.Equal(t, got.ShippedHash, sealed.ObjectMetadata()["shipped-hash"])
		})
	}
}

// Uploaded bytes are ciphertext, unparseable without the matching identity.
func TestObjectIsOpaqueWithoutTheIdentity(t *testing.T) {
	id := identity(t)
	stranger := identity(t)
	secretPath := "/Users/jane/.claude/projects/-Users-jane-work-secret/s.jsonl"

	m := manifest()
	m.NativePath = secretPath
	payload := []byte(`{"text":"a distinctive sentence that must not appear in ciphertext"}`)

	obj, _, err := Seal(m, payload, []age.Recipient{id.Recipient()})
	require.NoError(t, err)

	for _, needle := range []string{
		secretPath, "distinctive sentence", "claude-code-transcripts",
		"manifest.json", "jane", "payload",
	} {
		assert.NotContainsf(t, string(obj), needle, "ciphertext leaks %q in plaintext", needle)
	}
	_, _, openErr := Open(obj, stranger)
	require.Error(t, openErr, "an object must not open with an unrelated identity")
	_, _, excludedIdentityErr := Open(obj)
	require.Error(t, excludedIdentityErr, "opening with no identity must fail")
}

// A manifest that would fail downstream validation must not reach a bucket.
func TestSealValidatesTheManifestAgainstItsSchema(t *testing.T) {
	id := identity(t)
	for name, mutate := range map[string]func(*Manifest){
		"artifact class outside enum": func(m *Manifest) { m.ArtifactClass = "whatever" },
		"shape sniff outside enum":    func(m *Manifest) { m.ShapeSniff = "probably-fine" },
		"malformed source hash":       func(m *Manifest) { m.SourceHash = "deadbeef" },
		"derived without provenance":  func(m *Manifest) { m.Derived = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := manifest()
			mutate(&bad)
			_, _, err := Seal(bad, []byte("x"), []age.Recipient{id.Recipient()})
			require.Error(t, err)
		})
	}
}

// An object whose payload was altered after sealing must not open.
func TestOpenRejectsPayloadHashMismatch(t *testing.T) {
	id := identity(t)
	m := manifest()
	m.ShippedHash = strings.Repeat("b", 64)
	m.PayloadSize = 1
	raw, err := m.Encode()
	require.NoError(t, err)
	obj, err := writeContainer(raw, []byte("different"), nil, []age.Recipient{id.Recipient()})
	require.NoError(t, err)
	_, _, err = Open(obj, id)
	require.ErrorContains(t, err, "does not match manifest shipped_hash")
}

// Plaintext object metadata carries what a HEAD-side consumer dedupes on, and never the path.
func TestObjectMetadataNeverCarriesThePath(t *testing.T) {
	m := manifest()
	m.NativePath = "/Users/jane/.claude/projects/-Users-jane-work-secret-project/s.jsonl"
	m.ShippedHash = strings.Repeat("c", 64)

	md := m.ObjectMetadata()
	for _, needle := range []string{"jane", "secret-project", "s.jsonl", "/Users", "projects"} {
		for k, v := range md {
			assert.Truef(t, !strings.Contains(k, needle) && !strings.Contains(v, needle), "object metadata leaks %q: %v", needle, md)
		}
	}
	for _, want := range []string{"source-hash", "shipped-hash", "artifact-class", "manifest-version"} {
		if _, ok := md[want]; !ok {
			t.Errorf("object metadata should carry %q for HEAD-side dedupe", want)
		}
	}
}

// Explained enrich shortfalls survive a round trip, and a complete object's manifest omits them.
func TestTheManifestCarriesExplainedEnrichShortfalls(t *testing.T) {
	m := manifest()
	m.ShippedHash = strings.Repeat("b", 64)
	m.Derived = true
	m.Enricher = &EnricherRef{ID: "cursor-transcript-join", Version: 4}
	m.DerivedFrom = []string{strings.Repeat("a", 64)}
	m.EnrichStatus = "ok"
	raw, err := m.Encode()
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "enrich_repeats")
	assert.NotContains(t, string(raw), "enrich_tail")
	assert.NotContains(t, string(raw), "enrich_ambiguous")
	assert.NotContains(t, string(raw), "enrich_line_decode_errors")

	m.EnrichRepeats, m.EnrichTail, m.EnrichAmbiguous, m.EnrichLineDecodeErrors = 3, 1, 2, 4
	raw, err = m.Encode()
	require.NoError(t, err)
	for _, want := range []string{`"enrich_repeats":3`, `"enrich_tail":1`, `"enrich_ambiguous":2`, `"enrich_line_decode_errors":4`} {
		assert.Contains(t, string(raw), want)
	}
	back, err := DecodeManifest(raw)
	require.NoError(t, err)
	assert.Equal(t, m, back)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
