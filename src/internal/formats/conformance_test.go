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
	Vectors       []struct {
		Name          string `json:"name"`
		Key           string `json:"key"`
		CanonicalPath string `json:"canonical_path"`
		MirrorName    string `json:"mirror_name"`
	} `json:"vectors"`
}

func readJSON(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, into))
}

// The canonical encoding is the HMAC input: one byte of disagreement re-keys every file.
func TestConformanceCanonicalPath(t *testing.T) {
	var v canonicalPathVectors
	readJSON(t, "canonical-path.json", &v)
	require.NotEmpty(t, v.Vectors)
	for _, c := range v.Vectors {
		assert.Equalf(t, c.CanonicalPath, formats.CanonicalPath(c.SourceRelPath, c.Username), "%s: CanonicalPath(%q, %q)", c.Name, c.SourceRelPath, c.Username)
	}
}

func TestConformanceMirrorName(t *testing.T) {
	var v mirrorKeyVectors
	readJSON(t, "mirror-key.json", &v)
	require.NotEmpty(t, v.Vectors)
	for i, c := range v.Vectors {
		keyHex, ok := v.Keys[c.Key]
		require.Truef(t, ok, "vector %s names key %q, which is not in keys", c.Name, c.Key)
		key, err := hex.DecodeString(keyHex)
		require.NoError(t, err)
		got := formats.MirrorName(key, c.CanonicalPath)
		if *update {
			v.Vectors[i].MirrorName = got
			continue
		}
		assert.Equalf(t, c.MirrorName, got, "%s: MirrorName(%s, %q)", c.Name, c.Key, c.CanonicalPath)
	}
	if *update {
		b, err := json.MarshalIndent(v, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(vectorDir, "mirror-key.json"), append(b, '\n'), 0o644))
	}
}
