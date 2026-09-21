package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

func TestALocalLayerCanDisableAndEnableARegisteredEnricher(t *testing.T) {
	home := fakeHome(t)

	off, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: false
`)},
	))
	require.NoError(t, err)
	assert.True(t, !enrichersOf(off, "cursor-transcripts")["cursor-transcript-join"], "a local disable did not take effect")

	// And back on: enabling has to work from a local layer or the switch is one-way.
	on, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: true
`)},
	))
	require.NoError(t, err)
	assert.True(t, enrichersOf(on, "cursor-transcripts")["cursor-transcript-join"], "a local enable did not take effect")
}

// Toggling must not edit the compiled catalog. The two resolutions deliberately SHARE one
// *sources.Compiled: against two freshly loaded catalogs this would pass whether or not the clone exists.
func TestTogglingAnEnricherDoesNotMutateTheCompiledCatalog(t *testing.T) {
	home := fakeHome(t)
	shared := loadCatalog(t)

	first := config.Input{
		Catalog: shared,
		Layers: []config.LayeredDocument{{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: false
`)}},
		Env:      env(home, nil),
		StateDir: t.TempDir(),
	}
	if _, err := config.Resolve(first); err != nil {
		t.Fatal(err)
	}

	// The same catalog, no override: if the first resolution wrote through, this still sees the enricher disabled.
	clean, err := config.Resolve(config.Input{
		Catalog:  shared,
		Env:      env(home, nil),
		StateDir: t.TempDir(),
	})
	require.NoError(t, err)
	assert.True(t, enrichersOf(clean, "cursor-transcripts")["cursor-transcript-join"], "a previous resolution's override leaked into the compiled catalog")
}

func TestARemoteLayerMayDisableButNotEnableAnEnricher(t *testing.T) {
	home := fakeHome(t)

	// Disabling from the served document is fine: it only ever narrows.
	off, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: false
`)},
	))
	require.NoError(t, err)
	assert.True(t, !enrichersOf(off, "cursor-transcripts")["cursor-transcript-join"], "a remote layer could not disable an enricher, but narrowing is always allowed")

	// Enabling from a non-local layer would widen what gets read: an enricher reads a database the raw pipeline never touches.
	on, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: false
`)},
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
sources:
  - id: cursor-transcripts
    enrichers:
      cursor-transcript-join: true
`)},
	))
	require.NoError(t, err)
	assert.True(t, !enrichersOf(on, "cursor-transcripts")["cursor-transcript-join"], "a remote layer enabled an enricher the machine owner had switched off")
}

func TestALayerCannotAttachAnEnricherTheCatalogDidNot(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    enrichers:
      cursor-transcript-join: true
`)},
	))
	// Attaching an enricher the catalog never gave this source would let config decide which code reads which store.
	var rej *config.RejectionError
	require.ErrorAsf(t, err, &rej, "a layer attached an enricher the catalog did not: %v", err)
}

func TestTranscriptDisableDoesNotDisableAccountSource(t *testing.T) {
	eff, err := config.Resolve(baseInput(t, fakeHome(t), config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `sources:
  - id: codex-rollouts
    enabled: false
`)}))
	require.NoError(t, err)
	require.True(t, sourceByID(t, eff, "codex-account").Enabled, "account source coupled to transcripts")
}
