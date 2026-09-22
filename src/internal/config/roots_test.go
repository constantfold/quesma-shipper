package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// A root the compiled catalog never declared is refused: adding a genuinely new one takes a release.
func TestOutsideCeilingRootIsRejected(t *testing.T) {
	home := fakeHome(t)
	mustMkdir(t, filepath.Join(home, "evil", "projects"))

	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerRemote, `
sources:
  - id: claude-code-transcripts
    roots: ["~/evil"]
`),
	))
	require.Error(t, err, "a root outside the compiled ceiling must be rejected")
	assert.Containsf(t, err.Error(), "ceiling", "the refusal should explain the ceiling, got: %v", err)
}

// A user-layer adjustment within an already-compiled root family works with no recompilation.
func TestUserLayerMayNarrowWithinACompiledRoot(t *testing.T) {
	home := fakeHome(t)
	eff := resolved(t, home, layerDoc(t, config.LayerUser, `
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
`))
	assert.Equal(t, []string{"projects/**/*.jsonl"}, sourceByID(t, eff, "claude-code-transcripts").Include)
}

// A config whose include glob reaches a compiled-deny path is rejected and reported, not applied.
func TestIncludeReachingAgentCredentialsIsRejected(t *testing.T) {
	home := fakeHome(t)
	mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), `{"accessToken":"secret"}`)

	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerRemote, `
sources:
  - id: claude-code-transcripts
    include: ["**"]
`),
	))
	require.Error(t, err, "an include glob reaching .credentials.json must be rejected")
	assert.Containsf(t, err.Error(), "deny", "the refusal should name the deny list, got: %v", err)
}

// The deny list applies to the resolved path, so a symlink under an allowed root cannot launder a denied target.
func TestDenyFollowsSymlinksToTheirTarget(t *testing.T) {
	home := t.TempDir()
	secret := filepath.Join(home, ".ssh", "id_ed25519")
	mustWrite(t, secret, "PRIVATE KEY")

	link := filepath.Join(home, ".claude", "projects", "innocent.jsonl")
	mustMkdir(t, filepath.Dir(link))
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	d := sources.New(home)
	if ok, _ := d.Match(link); !ok {
		t.Fatal("a symlink whose target is denied must itself be denied")
	}
}

// The daemon resolves roots once and then ticks for days. Claude Code creates projects/ on its
// first run, which is routinely after the shipper started: without a refresh that install reports
// agent_absent forever, looking healthy while collecting nothing.
func TestRootResolutionLifecycle(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude"))
	eff := resolved(t, home)
	src := sourceByID(t, eff, "claude-code-transcripts")
	assert.Empty(t, src.Root)
	assert.Contains(t, src.RootUnresolvedReason, "projects")

	require.Empty(t, config.RefreshAbsentRoots(eff, env(home, nil)))
	assert.Empty(t, src.Root)
	assert.Contains(t, src.RootUnresolvedReason, "projects")

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

// Expansion is an attack surface: the deny list must act on the expanded value, never the template.
func TestEnvVarRootIsExpandedThenDenyChecked(t *testing.T) {
	home := fakeHome(t)
	in := baseInput(t, home)
	in.Env = env(home, map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(home, ".ssh")})

	_, err := config.Resolve(in)
	require.Error(t, err, "a root whose env var points into ~/.ssh must be rejected after expansion")
	assert.Containsf(t, err.Error(), "deny", "the refusal should name the deny list, got: %v", err)
}

// An unset variable is the normal case, not an error: the next candidate is tried.
func TestUnsetEnvVarFallsThroughToTheNextRoot(t *testing.T) {
	home := fakeHome(t)
	eff := resolved(t, home)
	src := sourceByID(t, eff, "claude-code-transcripts")
	assert.NotEmpty(t, src.Root, src.RootUnresolvedReason)
}

func TestRelativeExpansionIsRefused(t *testing.T) {
	home := fakeHome(t)
	e := env(home, map[string]string{"CLAUDE_CONFIG_DIR": "relative/path"})
	_, expandRootErr := e.ExpandRoot("$CLAUDE_CONFIG_DIR")
	require.Error(t, expandRootErr, "a root expanding to a relative path must be refused")
}

// A root that does not exist must not resolve: agent_absent has to stay separable from root_present_no_match.
func TestNonExistentRootDoesNotResolve(t *testing.T) {
	home := fakeHome(t) // has ~/.claude, deliberately no ~/.cursor

	eff := resolved(t, home)
	for _, s := range eff.Sources {
		if s.Family != "cursor" {
			continue
		}
		assert.Equalf(t, "", s.Root, "%s: root %q resolved although the directory does not exist", s.ID, s.Root)
		assert.Containsf(t, s.RootUnresolvedReason, "does not exist", "%s: reason should say the root is absent, got %q", s.ID, s.RootUnresolvedReason)
	}
}

// A file where a root directory is expected is not a store either.
func TestRootThatIsAFileDoesNotResolve(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".claude"), "not a directory")

	eff := resolved(t, home)
	for _, s := range eff.Sources {
		assert.Truef(t, s.Family != "claude-code" || s.Root == "", "%s: a regular file must not resolve as a root, got %q", s.ID, s.Root)
	}
}
