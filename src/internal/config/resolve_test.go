package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

// A clone-and-run install resolves with no config files and the compiled baseline in force.
func TestResolveWithNoConfigFilesWorks(t *testing.T) {
	home := fakeHome(t)
	eff := resolved(t, home)
	claude := sourceByID(t, eff, "claude-code-transcripts")
	assert.Equal(t, filepath.Join(home, ".claude"), claude.Root, claude.RootUnresolvedReason)
	assert.Equal(t, "default", eff.OrganizationID)
	// Asserted by name so a future trim of CompiledExemptions cannot silently drop a join key.
	for _, p := range []string{"toolUseId", "message.content[].id", "message.content[].tool_use_id"} {
		assert.Contains(t, eff.StructuralEx["claude-code"], p)
	}
}

func TestProvenanceAttributesEveryValue(t *testing.T) {
	eff := resolved(t, fakeHome(t),
		user(t, "mode:\n  schedule: \"5m\"\nsources:\n  - id: cursor-transcripts\n    enabled: false\n"),
		remote(t, "max_files_per_run: 32\n"))
	for field, layer := range map[string]config.Layer{
		"max_files_per_run":                       config.LayerRemote,
		"mode.schedule":                           config.LayerUser,
		"sources.cursor-transcripts.enabled":      config.LayerUser,
		"send.sink":                               config.LayerCompiledDefaults,
		"scrub.rule_packs":                        config.LayerCompiledDefaults,
		"sources.claude-code-transcripts.include": config.LayerBundledCatalog,
	} {
		assert.Equal(t, config.Origin{Layer: layer}, eff.Provenance[field], field)
	}
}

// A rejected layer refuses the whole resolution and names the field, never applies partly.
func TestResolveRejects(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		layer            func(*testing.T, string) config.LayeredDocument
		env              map[string]string
	}{
		{name: "unknown config_version", layer: remote, body: "config_version: 99\n", want: "config_version"},
		{name: "a layer inventing a source", layer: user, body: "sources:\n  - id: not-a-real-source\n    enabled: true\n"},
		// A bare number must not be guessed to mean seconds.
		{name: "zero drain deadline", layer: user, body: "drain_deadline: 0s\n"},
		{name: "negative drain deadline", layer: user, body: "drain_deadline: -30s\n"},
		{name: "unitless drain deadline", layer: user, body: "drain_deadline: 60\n"},
		// Rejecting at resolve time is what makes the refresh path fall back to the last valid config.
		{name: "local unparseable recipient", layer: user, body: "encryption:\n  additional_recipients: [not-an-age-key]\n"},
		{name: "served unparseable recipient", layer: remote, body: "encryption:\n  additional_recipients: [not-an-age-key]\n"},
		// Attaching an enricher the catalog never gave a source would let config decide which code reads which store.
		{name: "attaching an enricher", layer: user, body: "sources:\n  - id: claude-code-transcripts\n    enrichers:\n      cursor-transcript-join: true\n"},
		{name: "root outside the ceiling", layer: remote, body: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/evil\"]\n", want: "ceiling"},
		{name: "include reaching agent credentials", layer: remote, body: "sources:\n  - id: claude-code-transcripts\n    include: [\"**\"]\n", want: "deny"},
		// Expansion is an attack surface: the deny list acts on the expanded value, never the template.
		{name: "env root pointing into ~/.ssh", env: map[string]string{"CLAUDE_CONFIG_DIR": "HOME/.ssh"}, want: "deny"},
		{name: "env root expanding to a relative path", env: map[string]string{"CLAUDE_CONFIG_DIR": "relative/path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := fakeHome(t)
			mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), `{"accessToken":"secret"}`)
			in := input(t, home)
			if tc.layer != nil {
				in.Layers = append(in.Layers, tc.layer(t, tc.body))
			}
			for k, v := range tc.env {
				tc.env[k] = strings.Replace(v, "HOME", home, 1)
			}
			in.Env = env(home, tc.env)
			_, err := config.Resolve(in)
			mustReject(t, err, "")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The served document as renderConfig composes it, send: block included for the pre-vend fleet: refusing
// any field here makes the client refuse the WHOLE document, so the server must stop serving it first.
func TestServedDocumentWithAuthoredPartResolves(t *testing.T) {
	eff := resolved(t, fakeHome(t), remote(t, `
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
`))
	assert.Equal(t, "acme", eff.OrganizationID)
	assert.Equal(t, "30m", eff.Schedule)
	assert.Equal(t, 200, eff.MaxFilesPerRun)
	assert.Equal(t, config.LayerRemote, eff.Provenance["mode.schedule"].Layer)
}

// A served document may carry fields this build does not know; the local file may not, since a typo must not be a silent no-op.
func TestServedParseToleratesUnknownFieldsAndTheLocalParseDoesNot(t *testing.T) {
	const body = "config_version: 1\nsend:\n  sink: s3\n  bucket: acme-archive\nfuture_top_level: 7\n" +
		"mode:\n  schedule: \"5m\"\n  future_nested: yes\n"
	assert.Equal(t, "5m", resolved(t, fakeHome(t), remote(t, body)).Schedule)
	_, err := config.ParseDocument([]byte(body))
	require.Error(t, err)
	_, err = config.ParseDocument([]byte("max_file_per_run: 8\n"))
	require.Error(t, err)
}

// A config push touching only a redaction rule and the run budget must invalidate no fingerprints; a glob change resets exactly one source.
func TestSpecFingerprintCoversOnlyReadAffectingFields(t *testing.T) {
	home := fakeHome(t)
	before := resolved(t, home)
	unrelated := resolved(t, home, remote(t, "scrub:\n  rule_packs: [pii-core]\nmax_files_per_run: 8\n"))
	globbed := resolved(t, home, user(t, "sources:\n  - id: claude-code-transcripts\n    include: [\"projects/**/*.jsonl\"]\n"))
	for i, src := range before.Sources {
		assert.Equal(t, src.SpecFingerprint, unrelated.Sources[i].SpecFingerprint, src.ID)
		assert.Equal(t, src.ID == "claude-code-transcripts", src.SpecFingerprint != globbed.Sources[i].SpecFingerprint, src.ID)
	}
}

func TestEnricherEnablementAuthority(t *testing.T) {
	const join = "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: "
	for _, tc := range []struct {
		name, local, served string
		want                bool
	}{
		{"local disable", "false", "", false},
		{"local enable", "true", "", true},
		{"remote disable", "", "false", false},
		{"remote cannot undo local disable", "false", "true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var layers []config.LayeredDocument
			if tc.local != "" {
				layers = append(layers, user(t, join+tc.local))
			}
			if tc.served != "" {
				layers = append(layers, remote(t, join+tc.served))
			}
			eff := resolved(t, fakeHome(t), layers...)
			assert.Equal(t, tc.want, sourceByID(t, eff, "cursor-transcripts").Enrichers["cursor-transcript-join"])
		})
	}
}

// Both resolutions SHARE one *sources.Compiled: with two fresh catalogs this passes whether or not the map is cloned.
func TestTogglingAnEnricherDoesNotMutateTheCompiledCatalog(t *testing.T) {
	in := input(t, fakeHome(t), user(t, "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: false\n"))
	_, err := config.Resolve(in)
	require.NoError(t, err)
	in.Layers = nil
	clean, err := config.Resolve(in)
	require.NoError(t, err)
	assert.True(t, sourceByID(t, clean, "cursor-transcripts").Enrichers["cursor-transcript-join"])
}

func TestTranscriptDisableDoesNotDisableAccountSource(t *testing.T) {
	eff := resolved(t, fakeHome(t), user(t, "sources:\n  - id: codex-rollouts\n    enabled: false\n"))
	require.True(t, sourceByID(t, eff, "codex-account").Enabled, "account source coupled to transcripts")
}

// Claude Code creates projects/ on first run, often after the daemon resolved roots: without a refresh it stays agent_absent forever.
func TestRootResolutionLifecycle(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".claude"), 0o700))
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

func TestLoadLayers(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		layers     int
		wantErr    bool
	}{
		{name: "missing file is the clone-and-run case"},
		// Skipping an unreadable layer would silently drop the whole file.
		{name: "oversized file is refused", body: "config_version: 1\n# " + strings.Repeat("x", 1<<20) + "\n", wantErr: true},
		{name: "the send block older builds wrote still loads", body: "config_version: 1\nsend:\n  sink: file\n  path: /var/tmp/trajectory-archive\n", layers: 1},
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

func TestTickInterval(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		warn bool
	}{
		{"15m", 15 * time.Minute, false},
		{"90s", 90 * time.Second, false},
		{"1h", time.Hour, false},
		{"  10m  ", 10 * time.Minute, false}, // whitespace is not a meaning
		{"every day", config.DefaultTick, true},
		{"15", config.DefaultTick, true}, // bare number: ambiguous, and ParseDuration agrees
		{"-5m", config.DefaultTick, true},
		{"5s", config.MinTick, true}, // a poll loop at seconds is a hot loop
	} {
		got, warn := config.TickInterval(tc.in)
		assert.Equal(t, tc.want, got, tc.in)
		assert.Equal(t, tc.warn, warn != "", tc.in)
		if tc.warn {
			assert.Contains(t, warn, tc.in, "the warning must name the rejected value")
		}
	}
}
