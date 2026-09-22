package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

const joinOff = `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: false
`

const joinOn = `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: true
`

func TestEnricherEnablementAuthority(t *testing.T) {
	home := fakeHome(t)
	localOff := layerDoc(t, config.LayerUser, joinOff)
	for _, tc := range []struct {
		name   string
		layers []config.LayeredDocument
		want   bool
	}{
		{"local disable", []config.LayeredDocument{localOff}, false},
		{"local enable", []config.LayeredDocument{layerDoc(t, config.LayerUser, joinOn)}, true},
		{"remote disable", []config.LayeredDocument{layerDoc(t, config.LayerRemote, joinOff)}, false},
		{"remote cannot undo local disable", []config.LayeredDocument{localOff, layerDoc(t, config.LayerRemote, joinOn)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff := resolved(t, home, tc.layers...)
			assert.Equal(t, tc.want, sourceByID(t, eff, "cursor-transcripts").Enrichers["cursor-transcript-join"])
		})
	}
}

// Toggling must not edit the compiled catalog. The two resolutions deliberately SHARE one
// *sources.Compiled: against two freshly loaded catalogs this would pass whether or not the clone exists.
func TestTogglingAnEnricherDoesNotMutateTheCompiledCatalog(t *testing.T) {
	home := fakeHome(t)
	shared := loadCatalog(t)

	first := config.Input{
		Catalog:  shared,
		Layers:   []config.LayeredDocument{{Layer: config.LayerUser, Doc: doc(t, joinOff)}},
		Env:      env(home, nil),
		StateDir: t.TempDir(),
	}
	if _, err := config.Resolve(first); err != nil {
		t.Fatal(err)
	}

	// The same catalog, no override: if the first resolution wrote through, this still sees the enricher disabled.
	clean, err := config.Resolve(config.Input{Catalog: shared, Env: env(home, nil), StateDir: t.TempDir()})
	require.NoError(t, err)
	assert.True(t, sourceByID(t, clean, "cursor-transcripts").Enrichers["cursor-transcript-join"], "a previous resolution's override leaked into the compiled catalog")
}

func TestALayerCannotAttachAnEnricherTheCatalogDidNot(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerUser, `
sources:
  - id: claude-code-transcripts
    enrichers:
      cursor-transcript-join: true
`),
	))
	// Attaching an enricher the catalog never gave this source would let config decide which code reads which store.
	var rej *config.RejectionError
	require.ErrorAsf(t, err, &rej, "a layer attached an enricher the catalog did not: %v", err)
}

func TestTranscriptDisableDoesNotDisableAccountSource(t *testing.T) {
	eff := resolved(t, fakeHome(t), layerDoc(t, config.LayerUser, `sources:
  - id: codex-rollouts
    enabled: false
`))
	require.True(t, sourceByID(t, eff, "codex-account").Enabled, "account source coupled to transcripts")
}
