package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- harness ----------------------------------------------------------------

// fakeHome builds a home directory with a plausible Claude Code store, so root resolution has something real to act on.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude", "projects", "-Users-jane-work-api"))
	mustWrite(t, filepath.Join(home, ".claude", "projects", "-Users-jane-work-api", "s.jsonl"), "{}\n")
	mustWrite(t, filepath.Join(home, ".claude", "CLAUDE.md"), "# memory\n")
	return home
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatalf("compiled catalog must load and validate: %v", err)
	}
	return c
}

func doc(t *testing.T, y string) *config.Document {
	t.Helper()
	d, err := config.ParseDocument([]byte(y))
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	return d
}

// servedDoc parses the way the served path does: tolerant of fields this build does not know.
func servedDoc(t *testing.T, y string) *config.Document {
	t.Helper()
	d, err := config.ParseServedDocument([]byte(y))
	if err != nil {
		t.Fatalf("parse served document: %v", err)
	}
	return d
}

func baseInput(t *testing.T, home string, layers ...config.LayeredDocument) config.Input {
	t.Helper()
	return config.Input{
		Catalog:  loadCatalog(t),
		Layers:   layers,
		Env:      env(home, nil),
		StateDir: t.TempDir(),
	}
}

func user(t *testing.T, y string) config.LayeredDocument {
	t.Helper()
	return config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, y)}
}

func resolved(t *testing.T, home string, layers ...config.LayeredDocument) *config.Effective {
	t.Helper()
	eff, err := config.Resolve(baseInput(t, home, layers...))
	require.NoError(t, err)
	return eff
}

// --- baseline ---------------------------------------------------------------

func TestResolveWithNoConfigFilesWorks(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home))
	if err != nil {
		t.Fatalf("a clone-and-run install with no config files must resolve: %v", err)
	}

	var claude *config.ResolvedSource
	for i := range eff.Sources {
		if eff.Sources[i].ID == "claude-code-transcripts" {
			claude = &eff.Sources[i]
		}
	}
	if claude == nil {
		t.Fatal("claude-code-transcripts missing from the resolved set")
	}
	if claude.Root != filepath.Join(home, ".claude") {
		t.Errorf("root should resolve to the fake home store, got %q (%s)",
			claude.Root, claude.RootUnresolvedReason)
	}
	assert.Equal(t, "default", eff.OrganizationID)
	// Asserted by name so a future trim of CompiledExemptions cannot silently drop a join key.
	for _, p := range []string{"toolUseId", "message.content[].id", "message.content[].tool_use_id"} {
		assert.Contains(t, eff.StructuralEx["claude-code"], p)
	}
}

// Every value is attributable to the layer that set it.
func TestProvenanceAttributesEveryValue(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
mode:
  schedule: "5m"
sources:
  - id: cursor-transcripts
    enabled: false
`)},
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, `
max_files_per_run: 32
`)},
	))
	if err != nil {
		t.Fatal(err)
	}

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
		if got.Layer != layer {
			t.Errorf("%s: provenance %s, want %s", field, got.Layer, layer)
		}
		if got.Layer == 0 && !got.Derived {
			t.Errorf("%s: origin names no layer", field)
		}
	}
}

// A rejected layer refuses the whole resolution and names the field, never applies partly.
func TestResolveRejects(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		layer            func(*testing.T, string) config.LayeredDocument
		env              map[string]string
	}{
		{name: "unknown config_version", layer: served, body: "config_version: 99\n", want: "config_version"},
		{name: "a layer inventing a source", layer: user, body: "sources:\n  - id: not-a-real-source\n    enabled: true\n"},
		// A bare number must not be guessed to mean seconds.
		{name: "zero drain deadline", layer: user, body: "drain_deadline: 0s\n"},
		{name: "negative drain deadline", layer: user, body: "drain_deadline: -30s\n"},
		{name: "unitless drain deadline", layer: user, body: "drain_deadline: 60\n"},
		// Rejecting at resolve time is what makes the refresh path fall back to the last valid config.
		{name: "local unparseable recipient", layer: user, body: "encryption:\n  additional_recipients: [not-an-age-key]\n"},
		{name: "served unparseable recipient", layer: served, body: "encryption:\n  additional_recipients: [not-an-age-key]\n"},
		// Attaching an enricher the catalog never gave a source would let config decide which code reads which store.
		{name: "attaching an enricher", layer: user, body: "sources:\n  - id: claude-code-transcripts\n    enrichers:\n      cursor-transcript-join: true\n"},
		{name: "root outside the ceiling", layer: served, body: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/evil\"]\n", want: "ceiling"},
		{name: "include reaching agent credentials", layer: served, body: "sources:\n  - id: claude-code-transcripts\n    include: [\"**\"]\n", want: "deny"},
		// Expansion is an attack surface: the deny list acts on the expanded value, never the template.
		{name: "env root pointing into ~/.ssh", env: map[string]string{"CLAUDE_CONFIG_DIR": "HOME/.ssh"}, want: "deny"},
		{name: "env root expanding to a relative path", env: map[string]string{"CLAUDE_CONFIG_DIR": "relative/path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := fakeHome(t)
			mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), `{"accessToken":"secret"}`)
			in := baseInput(t, home)
			if tc.layer != nil {
				in.Layers = append(in.Layers, tc.layer(t, tc.body))
			}
			for k, v := range tc.env {
				tc.env[k] = strings.Replace(v, "HOME", home, 1)
			}
			in.Env = env(home, tc.env)
			_, err := config.Resolve(in)
			mustReject(t, err, tc.name)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// --- scope ceiling ----------------------------------------------------------

// The control plane's served document in the exact shape renderConfig composes it. This is the
// cross-repo contract: a field here that starts being refused makes the client refuse the WHOLE
// document and fall back to its cached config, so the server must stop serving it first. The
// send: block is the s3 one still served to the pre-vend fleet and has to keep LOADING here.
func TestServedDocumentWithAuthoredPartResolves(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, `
issued_at: 2026-08-12T10:00:00Z
org: acme
send:
  sink: s3
  bucket: acme-archive
  region: eu-central-1
encryption:
  additional_recipients:
    - age1rqcz770l8nugps6nxpz8lwgcrcqkcrz982jf6z6mjqlkvx6rgcssz7h2ys
mode:
  schedule: "30m"
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
scrub:
  rule_packs: [gitleaks-core]
max_files_per_run: 200
`)},
	))
	if err != nil {
		t.Fatalf("the served document must resolve: %v", err)
	}
	if eff.Schedule != "30m" {
		t.Errorf("mode.schedule = %q: the org's schedule did not take effect", eff.Schedule)
	}
	if eff.MaxFilesPerRun != 200 {
		t.Errorf("max_files_per_run = %d, want 200", eff.MaxFilesPerRun)
	}
	if got := eff.Provenance["mode.schedule"]; got.Layer != config.LayerRemote {
		t.Errorf("mode.schedule provenance %s, want the remote layer", got.Layer)
	}
	assert.Equal(t, "acme", eff.OrganizationID)
}

// --- require_subdir ---------------------------------------------------------

// Claude Code creates projects/ on first run, often after the daemon resolved roots: without a refresh it stays agent_absent forever.
func TestRootResolutionLifecycle(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude"))
	eff := resolved(t, home)
	src := sourceByID(t, eff, "claude-code-transcripts")
	for range 2 {
		assert.Empty(t, src.Root)
		assert.Contains(t, src.RootUnresolvedReason, "projects")
		require.Empty(t, config.RefreshAbsentRoots(eff, env(home, nil)))
	}

	mustWrite(t, filepath.Join(home, ".claude", "projects", "-Users-jane-api", "s.jsonl"), "{}\n")
	assert.Contains(t, config.RefreshAbsentRoots(eff, env(home, nil)), "claude-code-transcripts")
	assert.Equal(t, filepath.Join(home, ".claude"), src.Root)
	assert.Empty(t, src.RootUnresolvedReason)

	// Once selected, a root keeps the same fingerprint identity across later refreshes.
	for _, current := range []*config.Effective{eff, resolved(t, home)} {
		src := sourceByID(t, current, "claude-code-transcripts")
		before := src.Root
		require.NotEmpty(t, before)
		assert.NotContains(t, config.RefreshAbsentRoots(current, env(home, nil)), "claude-code-transcripts")
		assert.Equal(t, before, src.Root)
	}
}

// --- authority enforcement --------------------------------------------------

// The two parse paths on one document: a served document may carry fields this build does not know, the local file may not.
func TestServedParseToleratesUnknownFieldsAndTheLocalParseDoesNot(t *testing.T) {
	home := fakeHome(t)
	const body = "config_version: 1\n" +
		"send:\n  sink: s3\n  bucket: acme-archive\n" +
		"future_top_level: 7\n" +
		"mode:\n  schedule: \"5m\"\n  future_nested: yes\n"

	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, body)},
	))
	if err != nil {
		t.Fatalf("a served document with unknown fields must resolve: %v", err)
	}
	if eff.Schedule != "5m" {
		t.Errorf("the fields this build does know must still apply: schedule %q", eff.Schedule)
	}

	for _, local := range []string{body, "max_file_per_run: 8\n"} {
		if _, err := config.ParseDocument([]byte(local)); err == nil {
			t.Fatalf("the strict local parse accepted a field this build does not know: %q", local)
		}
	}
}

// --- the spec fingerprint gate ----------------------------------------------

// A config push touching only a redaction rule and the run budget must invalidate no fingerprints.
func TestSpecFingerprintCoversOnlyReadAffectingFields(t *testing.T) {
	home := fakeHome(t)

	before, err := config.Resolve(baseInput(t, home))
	if err != nil {
		t.Fatal(err)
	}

	// A push that changes a redaction rule and the run budget.
	unrelated, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
scrub:
  rule_packs: [pii-core]
max_files_per_run: 8
`)},
	))
	if err != nil {
		t.Fatal(err)
	}
	for i := range before.Sources {
		if before.Sources[i].SpecFingerprint != unrelated.Sources[i].SpecFingerprint {
			t.Errorf("%s: a redaction/budget push must not invalidate fingerprints",
				before.Sources[i].ID)
		}
	}

	// A glob change resets exactly one source.
	globbed, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
`)},
	))
	if err != nil {
		t.Fatal(err)
	}
	changed := 0
	for i := range before.Sources {
		if before.Sources[i].SpecFingerprint != globbed.Sources[i].SpecFingerprint {
			changed++
			if before.Sources[i].ID != "claude-code-transcripts" {
				t.Errorf("%s: an unrelated source's fingerprint changed", before.Sources[i].ID)
			}
		}
	}
	if changed != 1 {
		t.Errorf("a glob change should reset exactly one source, reset %d", changed)
	}
}

// --- documents --------------------------------------------------------------

// A missing root, or a file where one is expected, must not resolve: agent_absent has to stay separable from root_present_no_match.
func TestAbsentRootsDoNotResolve(t *testing.T) {
	for _, s := range resolved(t, fakeHome(t)).Sources { // fakeHome has no ~/.cursor
		if s.Family == "cursor" {
			assert.Empty(t, s.Root, s.ID)
			assert.Contains(t, s.RootUnresolvedReason, "does not exist", s.ID)
		}
	}
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".claude"), "not a directory")
	for _, s := range resolved(t, home).Sources {
		if s.Family == "claude-code" {
			assert.Empty(t, s.Root, s.ID)
		}
	}
}

// --- the enricher setting ---------------------------------------------------

func TestEnricherEnablementAuthority(t *testing.T) {
	const join = "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: "
	for _, tc := range []struct {
		name, local, remote string
		want                bool
	}{
		{"local disable", "false", "", false},
		{"local enable", "true", "", true},
		{"remote disable", "", "false", false},
		// An enricher reads a database the raw pipeline never touches, so only the machine owner may widen.
		{"remote cannot undo local disable", "false", "true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var layers []config.LayeredDocument
			if tc.local != "" {
				layers = append(layers, user(t, join+tc.local))
			}
			if tc.remote != "" {
				layers = append(layers, served(t, join+tc.remote))
			}
			eff := resolved(t, fakeHome(t), layers...)
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
	if err != nil {
		t.Fatal(err)
	}
	if !sourceByID(t, clean, "cursor-transcripts").Enrichers["cursor-transcript-join"] {
		t.Error("a previous resolution's override leaked into the compiled catalog")
	}
}

func TestTranscriptDisableDoesNotDisableAccountSource(t *testing.T) {
	eff, err := config.Resolve(baseInput(t, fakeHome(t), config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `sources:
  - id: codex-rollouts
    enabled: false
`)}))
	if err != nil {
		t.Fatal(err)
	}
	if !sourceByID(t, eff, "codex-account").Enabled {
		t.Fatal("account source coupled to transcripts")
	}
}
