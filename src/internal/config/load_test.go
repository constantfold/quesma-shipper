package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadLayers(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		layers     int
		wantErr    bool
	}{
		// A layer file that exists but cannot be read must refuse the whole resolution, never be silently dropped.
		{name: "oversized file is refused", body: "config_version: 1\n# " + strings.Repeat("x", 1<<20) + "\n", wantErr: true},
		// The strict local parse has to keep loading the `send:` block older builds wrote into config.yaml.
		{name: "the send block older builds wrote still loads", body: "config_version: 1\nsend:\n  sink: file\n  path: /var/tmp/trajectory-archive\n", layers: 1},
		{name: "missing file is the clone-and-run case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if tc.body != "" {
				mustWrite(t, path, tc.body)
			}
			layers, err := config.LoadLayers(config.Paths{User: path})
			if tc.wantErr {
				require.ErrorContains(t, err, path, "the refusal must name the offending file")
				return
			}
			require.NoError(t, err)
			assert.Len(t, layers, tc.layers)
		})
	}
}
