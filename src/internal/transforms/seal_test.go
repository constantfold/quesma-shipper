package transforms_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

func identity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id
}

func manifest() transforms.Manifest {
	return transforms.Manifest{
		ManifestVersion: transforms.ManifestVersion,
		OrganizationID:  "default",
		InstallID:       "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		SourceID:        "claude-code-transcripts",
		NativePath:      "/Users/__USER__/.claude/projects/-Users-__USER__-work-api/s.jsonl",
		Gather:          "file_glob",
		ArtifactClass:   "trajectory",
		SourceHash:      strings.Repeat("a", 64),
		SealedAt:        "2026-07-30T10:00:00Z",
		ShapeSniff:      "ok",
		Client:          transforms.Client{Version: "0.1.0", OS: "darwin", Arch: "arm64"},
		RunID:           "0123456789abcdef",
	}
}

// Every input must preserve payload, provenance and the hashes exposed in plaintext metadata.
func TestSealOpenRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		client  transforms.Client
	}{
		{"jsonl", []byte("{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n"), manifest().Client},
		{"empty", nil, manifest().Client},
		{"metadata hash", []byte("{\"line\":\"one\"}\n"), manifest().Client},
		{"stamped build", []byte("{}\n"), transforms.Client{
			Version: "0.0.0-d5f735643cbd+dirty", Commit: "d5f735643cbd3c70f71d2ed52746be1cadfe3a15",
			Modified: true, GoVersion: "go1.25.0", OS: "linux", Arch: "amd64",
		}},
		{"unstamped build", []byte("{}\n"), transforms.Client{Version: "unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := identity(t)
			m := manifest()
			m.Client = tc.client
			obj, sealed, err := transforms.Seal(m, tc.payload, []age.Recipient{id.Recipient()})
			require.NoError(t, err)
			got, payload, err := transforms.Open(obj, id)
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

// Manifest-first is the container contract and what makes a ranged head-fetch possible, so
// assert the order at the tar layer directly.
func TestManifestIsTheFirstTarEntry(t *testing.T) {
	id := identity(t)
	obj, _, err := transforms.Seal(manifest(), bytes.Repeat([]byte("x"), 4096), []age.Recipient{id.Recipient()})
	require.NoError(t, err)

	dec, err := age.Decrypt(bytes.NewReader(obj), id)
	require.NoError(t, err)
	zr, err := zstd.NewReader(dec)
	require.NoError(t, err)
	defer zr.Close()

	tr := tar.NewReader(zr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
	}
	if len(names) != 2 || names[0] != transforms.ManifestEntry || names[1] != transforms.PayloadEntry {
		t.Errorf("entries %v, want [%s %s]", names, transforms.ManifestEntry, transforms.PayloadEntry)
	}
}

// Real truncated ciphertext must yield the manifest or a distinguishable request for more bytes.
func TestManifestPrefixReads(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		seed int64
	}{
		{"six megabytes", 6 << 20, 1},
		{"one megabyte", 1 << 20, 2},
		{"two megabytes", 2 << 20, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := identity(t)
			// Incompressible bytes keep a prefix read from silently becoming a whole-object read.
			payload := make([]byte, tc.size)
			_, err := rand.New(rand.NewSource(tc.seed)).Read(payload)
			require.NoError(t, err)
			obj, _, err := transforms.Seal(manifest(), payload, []age.Recipient{id.Recipient()})
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(obj), 1<<20)

			m, err := transforms.ReadManifestPrefix(obj[:transforms.SuggestedPrefixBytes], id)
			require.NoError(t, err)
			assert.Equal(t, manifest().NativePath, m.NativePath)
			assert.Equal(t, manifest().SourceHash, m.SourceHash)
			assert.Equal(t, int64(len(payload)), m.PayloadSize)
			for _, n := range []int{1, 16, 128, 1024} {
				_, err := transforms.ReadManifestPrefix(obj[:n], id)
				assert.ErrorIs(t, err, transforms.ErrPrefixTooShort, "prefix bytes: %d", n)
			}

			for budget, attempts := 512, 1; ; budget, attempts = budget*2, attempts+1 {
				require.LessOrEqual(t, attempts, 20, "doubling did not converge")
				m, err := transforms.ReadManifestPrefix(obj[:min(budget, len(obj))], id)
				if err == nil {
					assert.Equal(t, "claude-code-transcripts", m.SourceID)
					break
				}
				require.ErrorIs(t, err, transforms.ErrPrefixTooShort, "prefix budget: %d", budget)
			}
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

	obj, _, err := transforms.Seal(m, payload, []age.Recipient{id.Recipient()})
	require.NoError(t, err)

	for _, needle := range []string{
		secretPath, "distinctive sentence", "claude-code-transcripts",
		"manifest.json", "jane", "payload",
	} {
		assert.NotContainsf(t, string(obj), needle, "ciphertext leaks %q in plaintext", needle)
	}
	if _, _, err := transforms.Open(obj, stranger); err == nil {
		t.Fatal("an object must not open with an unrelated identity")
	}
	if _, err := transforms.ReadManifestPrefix(obj, stranger); err == nil {
		t.Fatal("a manifest must not be readable with an unrelated identity")
	}
	if _, _, err := transforms.Open(obj); err == nil {
		t.Fatal("opening with no identity must fail")
	}
}

// Archival-only versus archival-plus-analysis recipients: who can read is decided at encryption
// time by which public recipients were included, and nothing later widens it.
func TestRecipientSetsDecideWhoCanRead(t *testing.T) {
	archival := identity(t)
	analysis := identity(t)
	payload := []byte(`{"a":1}`)

	archivalOnly, _, err := transforms.Seal(manifest(), payload, []age.Recipient{archival.Recipient()})
	require.NoError(t, err)
	both, _, err := transforms.Seal(manifest(), payload,
		[]age.Recipient{archival.Recipient(), analysis.Recipient()})
	require.NoError(t, err)

	if _, _, err := transforms.Open(archivalOnly, archival); err != nil {
		t.Errorf("the archival identity must read an archival object: %v", err)
	}
	if _, _, err := transforms.Open(archivalOnly, analysis); err == nil {
		t.Error("the analysis identity must NOT read an archival-only object")
	}
	for _, id := range []age.Identity{archival, analysis} {
		if _, _, err := transforms.Open(both, id); err != nil {
			t.Errorf("both recipients must read a two-recipient object: %v", err)
		}
	}

	// Recipient key IDs are recorded, public only, so a rotation can find what to rewrap.
	m, _, err := transforms.Open(both, archival)
	require.NoError(t, err)
	assert.Lenf(t, m.Encryption.RecipientKeyIDs, 2, "recipient_key_ids: %v", m.Encryption.RecipientKeyIDs)
	for _, kid := range m.Encryption.RecipientKeyIDs {
		require.NotContains(t, kid, "AGE-SECRET-KEY", "a private key reached the manifest")
	}
}

func TestSealRefusesWithNoRecipients(t *testing.T) {
	if _, _, err := transforms.Seal(manifest(), []byte("x"), nil); err == nil {
		t.Fatal("sealing with no recipients must fail: encryption is not optional")
	}
}

// A manifest that would fail downstream validation must not reach a bucket.
func TestSealValidatesTheManifestAgainstItsSchema(t *testing.T) {
	id := identity(t)
	for name, mutate := range map[string]func(*transforms.Manifest){
		"artifact class outside enum": func(m *transforms.Manifest) { m.ArtifactClass = "whatever" },
		"shape sniff outside enum":    func(m *transforms.Manifest) { m.ShapeSniff = "probably-fine" },
		"malformed source hash":       func(m *transforms.Manifest) { m.SourceHash = "deadbeef" },
		"derived without provenance":  func(m *transforms.Manifest) { m.Derived = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := manifest()
			mutate(&bad)
			_, _, err := transforms.Seal(bad, []byte("x"), []age.Recipient{id.Recipient()})
			require.Error(t, err)
		})
	}
}

// An object whose payload was altered after sealing must not open: the manifest describes
// bytes, so it has to describe THESE bytes.
func TestOpenRejectsPayloadHashMismatch(t *testing.T) {
	id := identity(t)

	// Build a container by hand with a manifest that lies about its payload.
	m := manifest()
	m.ShippedHash = strings.Repeat("b", 64)
	m.PayloadSize = 1
	raw, err := m.Encode()
	require.NoError(t, err)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, e := range []struct {
		name string
		body []byte
	}{{transforms.ManifestEntry, raw}, {transforms.PayloadEntry, []byte("different")}} {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: e.name, Size: int64(len(e.body)),
			Mode: 0o600, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR,
		}))
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	require.NoError(t, tw.Close())

	var objBuf bytes.Buffer
	encW, err := age.Encrypt(&objBuf, id.Recipient())
	require.NoError(t, err)
	zw, err := zstd.NewWriter(encW, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(transforms.ZstdLevel)))
	require.NoError(t, err)
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	encW.Close()

	if _, _, err := transforms.Open(objBuf.Bytes(), id); err == nil {
		t.Fatal("a payload that does not match shipped_hash must be refused")
	}
}

// Plaintext object metadata carries the hashes and versions a listing-side consumer dedupes
// on, and never the path.
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

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
