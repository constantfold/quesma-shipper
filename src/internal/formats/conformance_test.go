package formats_test

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// update regenerates the vector files (go test ./internal/formats -run Conformance -update).
// Never routine: a changed vector re-keys every previously shipped file and re-uploads it.
var update = flag.Bool("update", false, "regenerate the conformance vectors")

const vectorDir = "../../conformance/v1/naming"

type canonicalPathVectors struct {
	VectorSet     string `json:"vector_set"`
	VectorVersion int    `json:"vector_version"`
	Description   string `json:"description"`
	Vectors       []struct {
		Name          string `json:"name"`
		SourceRelPath string `json:"source_rel_path"`
		Username      string `json:"username"`
		CanonicalPath string `json:"canonical_path"`
	} `json:"vectors"`
}

type mirrorKeyVectors struct {
	VectorSet     string            `json:"vector_set"`
	VectorVersion int               `json:"vector_version"`
	Description   string            `json:"description"`
	Keys          map[string]string `json:"keys"`
	Vectors       []mirrorKeyVector `json:"vectors"`
}

type mirrorKeyVector struct {
	Name          string `json:"name"`
	Key           string `json:"key"`
	CanonicalPath string `json:"canonical_path"`
	MirrorName    string `json:"mirror_name"`
}

func readJSON(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	require.NoErrorf(t, err, "read vectors: %v", err)
	require.NoError(t, json.Unmarshal(raw, into))
}

// The canonical encoding is the HMAC input: one byte of disagreement re-keys every file.
func TestConformanceCanonicalPath(t *testing.T) {
	var v canonicalPathVectors
	readJSON(t, "canonical-path.json", &v)
	require.NotEqual(t, 0, len(v.Vectors), "no canonical-path vectors")
	for _, c := range v.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			got := formats.CanonicalPath(c.SourceRelPath, c.Username)
			assert.Equalf(t, c.CanonicalPath, got, "CanonicalPath(%q, %q)\n got %q\nwant %q", c.SourceRelPath, c.Username, got, c.CanonicalPath)
		})
	}
}

func TestConformanceMirrorName(t *testing.T) {
	path := filepath.Join(vectorDir, "mirror-key.json")

	if *update {
		require.NoError(t, os.WriteFile(path, generateMirrorKeyVectors(t), 0o644))
		t.Logf("regenerated %s", path)
	}

	var v mirrorKeyVectors
	readJSON(t, "mirror-key.json", &v)
	require.NotEqual(t, 0, len(v.Vectors), "no mirror-key vectors")
	for _, c := range v.Vectors {
		t.Run(c.Name, func(t *testing.T) {
			keyHex, ok := v.Keys[c.Key]
			if !ok {
				t.Fatalf("vector names key %q, which is not in keys", c.Key)
			}
			key, err := hex.DecodeString(keyHex)
			require.NoError(t, err)
			got := formats.MirrorName(key, c.CanonicalPath)
			assert.Equalf(t, c.MirrorName, got, "MirrorName(%s, %q)\n got %s\nwant %s", c.Key, c.CanonicalPath, got, c.MirrorName)
		})
	}
}

func generateMirrorKeyVectors(t *testing.T) []byte {
	t.Helper()
	var out mirrorKeyVectors
	readJSON(t, "mirror-key.json", &out)
	for i := range out.Vectors {
		c := &out.Vectors[i]
		keyHex, ok := out.Keys[c.Key]
		require.Truef(t, ok, "vector names unknown key %q", c.Key)
		key, err := hex.DecodeString(keyHex)
		require.NoError(t, err)
		c.MirrorName = formats.MirrorName(key, c.CanonicalPath)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)
	return append(b, '\n')
}
