package transforms

import (
	"archive/tar"
	"bytes"
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
)

const vectorPath = "../../conformance/v1/seal/container.json"

// containerVectors fixes the tar layer, which is deterministic and holds the contract that
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
	Name         string `json:"name"`
	ManifestJSON string `json:"manifest_json"`
	PayloadHex   string `json:"payload_hex"`
	TarSHA256    string `json:"tar_sha256"`
}

func TestConformanceContainerLayout(t *testing.T) {
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(vectorPath), 0o755))
		require.NoError(t, os.WriteFile(vectorPath, generateContainerVectors(t), 0o644))
		t.Logf("regenerated %s", vectorPath)
	}

	var v containerVectors
	readVectors(t, vectorPath, &v)

	assert.Equalf(t, ZstdLevel, v.ZstdLevel, "zstd level drifted: vector says %d, code says %d", v.ZstdLevel, ZstdLevel)
	require.Equal(t, []string{ManifestEntry, PayloadEntry}, v.EntryOrder)

	for _, c := range v.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			payload, err := hex.DecodeString(c.PayloadHex)
			require.NoError(t, err)
			got := tarBytesFor(t, []byte(c.ManifestJSON), payload)
			assert.Equal(t, c.TarSHA256, sha256Hex(got), "tar layer bytes changed")
		})
	}
}

// tarBytesFor recovers the tar layer from a real sealed object, so the vector checks what Seal
// writes rather than a reimplementation.
func tarBytesFor(t *testing.T, manifestJSON, payload []byte) []byte {
	t.Helper()

	var m Manifest
	require.NoError(t, json.Unmarshal(manifestJSON, &m))
	id := identity(t)
	obj, _, err := Seal(m, payload, []age.Recipient{id.Recipient()})
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
		if hdr.Name == ManifestEntry {
			var m map[string]any
			require.NoError(t, json.Unmarshal(body, &m))
			delete(m, "encryption")
			body, err = json.Marshal(m)
			require.NoError(t, err)
			hdr.Size = int64(len(body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, writeErr := tw.Write(body)
		require.NoError(t, writeErr)
	}
	require.NoError(t, tw.Close())
	return out.Bytes()
}

func generateContainerVectors(t *testing.T) []byte {
	t.Helper()
	var out containerVectors
	readVectors(t, vectorPath, &out)
	out.EntryOrder = []string{ManifestEntry, PayloadEntry}
	out.ZstdLevel = ZstdLevel
	for i := range out.Vectors {
		c := &out.Vectors[i]
		payload, err := hex.DecodeString(c.PayloadHex)
		require.NoError(t, err)
		var m Manifest
		require.NoError(t, json.Unmarshal([]byte(c.ManifestJSON), &m))
		m.ShippedHash, m.PayloadSize = sha256Hex(payload), int64(len(payload))
		encoded, err := json.Marshal(m)
		require.NoError(t, err)
		c.ManifestJSON = string(encoded)
		c.TarSHA256 = sha256Hex(tarBytesFor(t, encoded, payload))
	}
	return encodeVectors(t, out)
}
