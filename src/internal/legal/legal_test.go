package legal

import (
	"bytes"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The embedded copies must match the repository's canonical files, or `quesma-shipper licenses` lies.
func TestEmbeddedCopiesMatchRepository(t *testing.T) {
	for name, canonical := range map[string]string{"LICENSE": "../../../LICENSE", "NOTICE": "../../../NOTICE"} {
		want, err := os.ReadFile(canonical)
		require.NoError(t, err)
		got, err := FS.ReadFile(name)
		require.NoError(t, err)
		assert.Truef(t, bytes.Equal(got, want), "%s differs from %s; run make licenses", name, canonical)
	}
}

// Every row of the inventory has a license text in the tree, and the tree has no orphan.
func TestInventoryMatchesTexts(t *testing.T) {
	csv, err := FS.ReadFile("third_party/licenses.csv")
	require.NoError(t, err)
	for _, line := range strings.Split(strings.TrimSpace(string(csv)), "\n") {
		pkg := strings.SplitN(line, ",", 2)[0]
		found := false
		for p := pkg; p != "." && p != ""; p = path.Dir(p) {
			if entries, err := FS.ReadDir("third_party/licenses/" + p); err == nil && len(entries) > 0 {
				found = true
				break
			}
		}
		assert.Truef(t, found, "%s is in licenses.csv but has no license text under third_party/licenses", pkg)
	}
	var out bytes.Buffer
	require.NoError(t, Write(&out))
	for _, must := range []string{"Copyright 2026 Quesma Inc.", "Apache License", "The Update Framework Authors", "mousetrap", "Zachary Rice"} {
		assert.Containsf(t, out.String(), must, "licenses output lacks %q", must)
	}
}
