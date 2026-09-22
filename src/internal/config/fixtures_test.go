package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// fakeHome builds a home directory with a plausible Claude Code store, so root resolution has something real to act on.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".claude", "projects", "-Users-jane-work-api", "s.jsonl"), "{}\n")
	mustWrite(t, filepath.Join(home, ".claude", "CLAUDE.md"), "# memory\n")
	return home
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(p, 0o700))
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(p))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}

func env(home string, vars map[string]string) sources.Env {
	return sources.Env{
		Home: home,
		Lookup: func(k string) (string, bool) {
			v, ok := vars[k]
			return v, ok
		},
	}
}

func loadCatalog(t *testing.T) *sources.Compiled {
	t.Helper()
	c, err := sources.Load()
	require.NoErrorf(t, err, "compiled catalog must load and validate: %v", err)
	return c
}

func doc(t *testing.T, y string) *config.Document {
	t.Helper()
	d, err := config.ParseDocument([]byte(y))
	require.NoErrorf(t, err, "parse document: %v", err)
	return d
}

// servedDoc parses the way the served path does: tolerant of fields this build does not know.
func servedDoc(t *testing.T, y string) *config.Document {
	t.Helper()
	d, err := config.ParseServedDocument([]byte(y))
	require.NoErrorf(t, err, "parse served document: %v", err)
	return d
}

func layerDoc(t *testing.T, layer config.Layer, body string) config.LayeredDocument {
	t.Helper()
	return config.LayeredDocument{Layer: layer, Doc: doc(t, body)}
}

func servedLayer(t *testing.T, layer config.Layer, body string) config.LayeredDocument {
	t.Helper()
	return config.LayeredDocument{Layer: layer, Doc: servedDoc(t, body)}
}

func baseInput(t *testing.T, home string, layers ...config.LayeredDocument) config.Input {
	t.Helper()
	return config.Input{Catalog: loadCatalog(t), Layers: layers, Env: env(home, nil), StateDir: t.TempDir()}
}

func resolved(t *testing.T, home string, layers ...config.LayeredDocument) *config.Effective {
	t.Helper()
	eff, err := config.Resolve(baseInput(t, home, layers...))
	require.NoError(t, err)
	return eff
}

func sourceByID(t *testing.T, eff *config.Effective, id string) *config.ResolvedSource {
	t.Helper()
	for i := range eff.Sources {
		if eff.Sources[i].ID == id {
			return &eff.Sources[i]
		}
	}
	t.Fatalf("source %s missing from the resolved set", id)
	return nil
}
