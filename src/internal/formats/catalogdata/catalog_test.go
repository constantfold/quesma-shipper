package catalogdata_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats/catalogdata"
)

func validate(t *testing.T, raw []byte) error {
	t.Helper()
	var doc any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	return formats.Validate(formats.SourceSpec, doc)
}

// Without these refusals, TestBundledSourceRules could be green with the validator inert.
func TestSchemaRejectsBadCatalogFiles(t *testing.T) {
	const valid = "spec_version: 1\nfamily: demo\nsources:\n  - id: demo-src\n    gather: file_glob\n" +
		"    artifact_class: trajectory\n    roots: [\"~/.demo\"]\n    include: [\"**/*.jsonl\"]\n"
	require.NoError(t, validate(t, []byte(valid)))
	for name, edit := range map[string][2]string{
		"unknown gather name":                  {"gather: file_glob", "gather: sqlite_rows"},
		"reserved gather name":                 {"gather: file_glob", "gather: acp"},
		"missing artifact_class":               {"    artifact_class: trajectory\n", ""},
		"walking primitive without roots":      {"    roots: [\"~/.demo\"]\n", ""},
		"unknown source field":                 {"    include:", "    container: mirror\n    include:"},
		"undeclared change_detection strategy": {"    include:", "    change_detection: append_offset\n    include:"},
		"unknown spec_version":                 {"spec_version: 1", "spec_version: 2"},
	} {
		changed := strings.Replace(valid, edit[0], edit[1], 1)
		require.NotEqual(t, valid, changed, name)
		assert.Error(t, validate(t, []byte(changed)), name)
	}
	sidecar := "spec_version: 1\nfamily: demo\nsources:\n  - id: demo-src\n    gather: sidecar\n    artifact_class: context\n    emit: git_project_map\n"
	assert.Error(t, validate(t, []byte(sidecar)), "sidecar without a bounded probe")
}

// Every bundled catalog file validates, since it is edited by people who do not read Go, and meets the rules the schema cannot express.
func TestBundledSourceRules(t *testing.T) {
	files, err := fs.Glob(catalogdata.FS, "*.yaml")
	require.NoError(t, err)
	// Group 1 is the v1 scope ceiling: Claude Code, Codex, Cursor.
	assert.Subset(t, files, []string{"claude-code.yaml", "codex.yaml", "cursor.yaml"})
	seen := map[string]string{}
	cursorJoin := false
	for _, name := range files {
		raw, err := catalogdata.FS.ReadFile(name)
		require.NoError(t, err)
		assert.NoError(t, validate(t, raw), name)
		var doc struct {
			Sources []struct {
				ID           string          `yaml:"id"`
				Gather       string          `yaml:"gather"`
				Class        string          `yaml:"artifact_class"`
				Include      []string        `yaml:"include"`
				MaxFileBytes int64           `yaml:"max_file_bytes"`
				Enrichers    map[string]bool `yaml:"enrichers"`
			} `yaml:"sources"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &doc))
		for _, s := range doc.Sources {
			// Source ids key both object keys and fingerprint state, so a collision merges two sources.
			assert.NotContainsf(t, seen, s.ID, "source id %q appears in both %s and %s", s.ID, seen[s.ID], name)
			seen[s.ID] = name
			// SQLite is enricher input only: no catalog entry may name a database as a shipping source.
			assert.NotContains(t, s.Gather, "sqlite", s.ID)
			for _, g := range s.Include {
				for _, ext := range []string{".vscdb", ".sqlite", ".db"} {
					assert.NotContains(t, g, ext, s.ID)
				}
			}
			assert.Contains(t, []string{"trajectory", "context"}, s.Class, s.ID)
			// The pipeline holds a payload several times over, so a whole-file reader without a cap is an OOM.
			if s.Gather == "file_glob" {
				assert.Positivef(t, s.MaxFileBytes, "%s reads whole files and declares no max_file_bytes", s.ID)
			}
			// Cursor's DB-side fidelity reaches the sink only through the enricher.
			if s.ID == "cursor-transcripts" {
				cursorJoin = s.Enrichers["cursor-transcript-join"]
			}
		}
	}
	assert.True(t, cursorJoin, "cursor-transcripts must enable cursor-transcript-join")
}
