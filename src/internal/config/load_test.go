package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

// A layer file that exists but cannot be read must refuse the whole resolution, never be silently dropped.
func TestLoadLayersRefusesAnUnreadableLayer(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "config.yaml")
	body := "config_version: 1\n# " + strings.Repeat("x", 1<<20) + "\n"
	require.NoError(t, os.WriteFile(user, []byte(body), 0o600))

	_, err := config.LoadLayers(config.Paths{User: user})
	require.Error(t, err, "an oversized config layer was silently dropped")
	assert.Containsf(t, err.Error(), user, "the refusal does not name the offending file: %v", err)
}

// The strict local parse has to keep loading the `send:` block older builds wrote into config.yaml.
func TestLoadLayersAcceptsTheSendBlockOlderBuildsWrote(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "config.yaml")
	body := "config_version: 1\nsend:\n  sink: file\n  path: /var/tmp/trajectory-archive\n"
	require.NoError(t, os.WriteFile(user, []byte(body), 0o600))

	layers, err := config.LoadLayers(config.Paths{User: user})
	require.NoErrorf(t, err, "a config.yaml an older build wrote no longer loads: %v", err)
	require.Lenf(t, layers, 1, "got %d layers, want the user layer", len(layers))
}

// A missing file stays the clone-and-run case: no layers, no error.
func TestLoadLayersSkipsAMissingFile(t *testing.T) {
	layers, err := config.LoadLayers(config.Paths{User: filepath.Join(t.TempDir(), "absent.yaml")})
	require.Truef(t, err == nil && len(layers) == 0, "a missing file returned layers=%d err=%v", len(layers), err)
}
