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

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}

func env(home string, vars map[string]string) sources.Env {
	return sources.Env{Home: home, Lookup: func(k string) (string, bool) { v, ok := vars[k]; return v, ok }}
}

// user parses strictly, as the machine owner's file is; remote parses the way the served path does.
func user(t *testing.T, y string) config.LayeredDocument {
	t.Helper()
	d, err := config.ParseDocument([]byte(y))
	require.NoError(t, err)
	return config.LayeredDocument{Layer: config.LayerUser, Doc: d}
}

func remote(t *testing.T, y string) config.LayeredDocument {
	t.Helper()
	d, err := config.ParseServedDocument([]byte(y))
	require.NoError(t, err)
	return config.LayeredDocument{Layer: config.LayerRemote, Doc: d}
}

func input(t *testing.T, home string, layers ...config.LayeredDocument) config.Input {
	t.Helper()
	c, err := sources.Load()
	require.NoError(t, err, "compiled catalog must load and validate")
	return config.Input{Catalog: c, Layers: layers, Env: env(home, nil), StateDir: t.TempDir()}
}

func resolve(t *testing.T, home string, layers ...config.LayeredDocument) (*config.Effective, error) {
	t.Helper()
	return config.Resolve(input(t, home, layers...))
}

func resolved(t *testing.T, home string, layers ...config.LayeredDocument) *config.Effective {
	t.Helper()
	eff, err := resolve(t, home, layers...)
	require.NoError(t, err)
	return eff
}

func mustReject(t *testing.T, err error, field string) {
	t.Helper()
	var rej *config.RejectionError
	require.ErrorAs(t, err, &rej, "want a *RejectionError")
	if field != "" {
		require.Equal(t, field, rej.Field)
	}
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
