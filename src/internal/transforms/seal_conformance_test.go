package transforms_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

const vectorPath = "../../conformance/v1/seal/container.json"

// containerVectors pins the tar layer, which is deterministic and holds the contract that
// matters: entry order, entry names, normalised headers. zstd output moves with the encoder
// version and age is nondeterministic by design, so whole-object bytes are covered by round-trip
// and opacity tests instead.
type containerVectors struct {
	VectorSet     string          `json:"vector_set"`
	VectorVersion int             `json:"vector_version"`
	Description   string          `json:"description"`
	LayerOrder    []string        `json:"layer_order"`
	EntryOrder    []string        `json:"entry_order"`
	ZstdLevel     int             `json:"zstd_level"`
	TarHeader     tarHeaderVector `json:"tar_header_normalization"`
	Vectors       []tarVector     `json:"vectors"`
}

type tarHeaderVector struct {
	Mode            string `json:"mode"`
	UIDGID          int    `json:"uid_gid"`
	Format          string `json:"format"`
	ManifestModTime string `json:"manifest_mod_time"`
}

type tarVector struct {
	Name        string `json:"name"`
	ManifestB64 string `json:"manifest_json"`
	PayloadHex  string `json:"payload_hex"`
	TarSHA256   string `json:"tar_sha256"`
}

func TestConformanceContainerLayout(t *testing.T) {
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(vectorPath), 0o755))
		require.NoError(t, os.WriteFile(vectorPath, generateContainerVectors(t), 0o644))
		t.Logf("regenerated %s", vectorPath)
	}

	raw, err := os.ReadFile(vectorPath)
	require.NoErrorf(t, err, "read vectors: %v", err)
	var v containerVectors
	require.NoError(t, json.Unmarshal(raw, &v))

	assert.Equalf(t, transforms.ZstdLevel, v.ZstdLevel, "zstd level drifted: vector says %d, code says %d", v.ZstdLevel, transforms.ZstdLevel)
	want := []string{transforms.ManifestEntry, transforms.PayloadEntry}
	for i, name := range want {
		require.Truef(t, i <= len(v.EntryOrder) && v.EntryOrder[i] == name, "entry order drifted: %v, want %v", v.EntryOrder, want)
	}

	for _, c := range v.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			payload, err := hex.DecodeString(c.PayloadHex)
			require.NoError(t, err)
			got := tarBytesFor(t, []byte(c.ManifestB64), payload)
			sum := sha256.Sum256(got)
			assert.Equalf(t, c.TarSHA256, hex.EncodeToString(sum[:]), "tar layer bytes changed:\n got %s\nwant %s", hex.EncodeToString(sum[:]), c.TarSHA256)
		})
	}
}

// tarBytesFor recovers the tar layer from a real sealed object, so the vector pins what Seal
// writes rather than a reimplementation.
func tarBytesFor(t *testing.T, manifestJSON, payload []byte) []byte {
	t.Helper()

	var m transforms.Manifest
	require.NoError(t, json.Unmarshal(manifestJSON, &m))
	id := identity(t)
	obj, _, err := transforms.Seal(m, payload, []age.Recipient{id.Recipient()})
	require.NoError(t, err)

	dec, err := age.Decrypt(bytes.NewReader(obj), id)
	require.NoError(t, err)
	zr, err := zstd.NewReader(dec)
	require.NoError(t, err)
	defer zr.Close()

	tarred, err := io.ReadAll(zr)
	require.NoError(t, err)

	// Recipient key IDs differ per run, so rebuild the tar with them blanked, which is what the
	// vector records.
	return normalizeTar(t, tarred)
}

// normalizeTar removes the manifest's per-run fields, leaving the structure the vector is about.
func normalizeTar(t *testing.T, tarred []byte) []byte {
	t.Helper()

	tr := tar.NewReader(bytes.NewReader(tarred))
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		if hdr.Name == transforms.ManifestEntry {
			var m map[string]any
			require.NoError(t, json.Unmarshal(body, &m))
			delete(m, "encryption")
			body, err = json.Marshal(m)
			require.NoError(t, err)
			hdr.Size = int64(len(body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	require.NoError(t, tw.Close())
	return out.Bytes()
}

func generateContainerVectors(t *testing.T) []byte {
	t.Helper()

	cases := []struct {
		name    string
		mutate  func(*transforms.Manifest)
		payload []byte
	}{
		{"jsonl transcript", nil, []byte("{\"type\":\"user\"}\n{\"type\":\"assistant\"}\n")},
		{"empty payload", nil, nil},
		{"derived enricher output", func(m *transforms.Manifest) {
			m.Derived = true
			m.Enricher = &transforms.EnricherRef{ID: "cursor-transcript-join", Version: 1}
			m.DerivedFrom = []string{hexRepeat("a")}
			m.EnrichStatus = "ok"
			m.NativePath = "/c8cbeb0b/c8cbeb0b.jsonl.enriched.jsonl"
		}, []byte("{\"_enrich\":{}}\n")},
	}

	out := containerVectors{
		VectorSet:     "container",
		VectorVersion: 1,
		Description: "Object container layout: tar(manifest.json FIRST, payload) -> zstd level 3 -> age. " +
			"Manifest-first is what makes a ranged GET of the object head yield the whole manifest, which " +
			"is why no manifest sidecar object exists. Only the tar layer is byte-pinned here: zstd output " +
			"depends on the encoder version and age is nondeterministic by design, so those layers are " +
			"covered by round-trip and opacity tests instead. The manifest's encryption block is removed " +
			"before hashing because recipient key IDs differ per run.",
		LayerOrder: []string{"tar", "zstd", "age"},
		EntryOrder: []string{transforms.ManifestEntry, transforms.PayloadEntry},
		ZstdLevel:  transforms.ZstdLevel,
		TarHeader: tarHeaderVector{
			Mode:            "0600",
			UIDGID:          0,
			Format:          "USTAR",
			ManifestModTime: "1970-01-01T00:00:00Z",
		},
	}

	for _, c := range cases {
		m := manifest()
		if c.mutate != nil {
			c.mutate(&m)
		}
		// Fill the fields Seal would compute, so the recorded manifest is the one that lands.
		sum := sha256.Sum256(c.payload)
		m.ShippedHash = hex.EncodeToString(sum[:])
		m.PayloadSize = int64(len(c.payload))

		encoded, err := json.Marshal(m)
		require.NoError(t, err)
		tarred := tarBytesFor(t, encoded, c.payload)
		tarSum := sha256.Sum256(tarred)

		out.Vectors = append(out.Vectors, tarVector{
			Name:        c.name,
			ManifestB64: string(encoded),
			PayloadHex:  hex.EncodeToString(c.payload),
			TarSHA256:   hex.EncodeToString(tarSum[:]),
		})
	}

	b, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)
	return append(b, '\n')
}

func hexRepeat(c string) string {
	out := ""
	for range 64 {
		out += c
	}
	return out
}
