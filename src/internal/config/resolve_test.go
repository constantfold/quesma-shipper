package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

func TestResolveWithNoConfigFilesWorks(t *testing.T) {
	home := fakeHome(t)
	eff := resolved(t, home)

	var claude *config.ResolvedSource
	for i := range eff.Sources {
		if eff.Sources[i].ID == "claude-code-transcripts" {
			claude = &eff.Sources[i]
		}
	}
	require.True(t, claude != nil, "claude-code-transcripts missing from the resolved set")
	assert.Equalf(t, filepath.Join(home, ".claude"), claude.Root, "root should resolve to the fake home store, got %q (%s)", claude.Root, claude.RootUnresolvedReason)
}

// Every value is attributable to the layer that set it.
func TestProvenanceAttributesEveryValue(t *testing.T) {
	home := fakeHome(t)
	eff := resolved(t, home, layerDoc(t, config.LayerUser, `
mode:
  schedule: "5m"
sources:
  - id: cursor-transcripts
    enabled: false
`), servedLayer(t, config.LayerRemote, `
max_files_per_run: 32
`))

	want := map[string]config.Layer{
		"max_files_per_run":                       config.LayerRemote,
		"mode.schedule":                           config.LayerUser,
		"sources.cursor-transcripts.enabled":      config.LayerUser,
		"send.sink":                               config.LayerCompiledDefaults,
		"scrub.rule_packs":                        config.LayerCompiledDefaults,
		"sources.claude-code-transcripts.include": config.LayerBundledCatalog,
	}
	for field, layer := range want {
		got, ok := eff.Provenance[field]
		if !ok {
			t.Errorf("%s has no provenance recorded", field)
			continue
		}
		assert.Equalf(t, layer, got.Layer, "%s: provenance %s, want %s", field, got.Layer, layer)
		assert.Truef(t, got.Layer != 0 || got.Derived, "%s: origin names no layer", field)
	}
}

func TestUnknownConfigVersionIsAHardError(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerRemote, "config_version: 99\n"),
	))
	require.Error(t, err, "an unknown config_version must be a hard error, never a partial application")
	assert.Containsf(t, err.Error(), "config_version", "the refusal should name the field, got: %v", err)
}

// A typo in a security-relevant config file must not be a silent no-op.
func TestUnknownFieldInADocumentIsRefused(t *testing.T) {
	if _, err := config.ParseDocument([]byte("max_file_per_run: 8\n")); err == nil {
		t.Fatal("an unknown config field must be refused, not ignored")
	}
}

func TestSourceOverrideForUnknownSourceIsRefused(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerUser, `
sources:
  - id: not-a-real-source
    enabled: true
`),
	))
	require.Error(t, err, "a config layer must not be able to invent a source")
}

func TestDrainDeadlineParses(t *testing.T) {
	home := fakeHome(t)

	// Distinct from the default, so the assertion can only pass by parsing the document.
	eff := resolved(t, home, layerDoc(t, config.LayerUser, "drain_deadline: 90s\n"))
	assert.Equalf(t, 90*time.Second, eff.DrainDeadline, "drain_deadline = %s, want 90s", eff.DrainDeadline)
}

func TestANonPositiveDrainDeadlineIsRejected(t *testing.T) {
	home := fakeHome(t)
	for _, spelling := range []string{"0s", "-30s"} {
		// A zero or negative deadline makes every drain a silent no-op, losing the data the drain exists to save.
		_, err := config.Resolve(baseInput(t, home,
			layerDoc(t, config.LayerUser, "drain_deadline: "+spelling+"\n"),
		))
		var rej *config.RejectionError
		assert.ErrorAsf(t, err, &rej, "drain_deadline %s was accepted: %v", spelling, err)
	}
}

func TestAnUnparseableDrainDeadlineIsRejected(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerUser, "drain_deadline: 60\n"),
	))
	// Bare "60" is the plausible mistake, and guessing at seconds would mean a config that means something else.
	var rej *config.RejectionError
	require.ErrorAsf(t, err, &rej, "drain_deadline: 60 was accepted: %v", err)
}
