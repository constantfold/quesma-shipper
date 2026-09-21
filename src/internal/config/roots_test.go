package config_test

import (
	"os"
	"path/filepath"
	"slices"
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
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    roots: ["~/evil"]
`)},
	))
	require.Error(t, err, "a root outside the compiled ceiling must be rejected")
	assert.Containsf(t, err.Error(), "ceiling", "the refusal should explain the ceiling, got: %v", err)
}

// A user-layer adjustment within an already-compiled root family works with no recompilation.
func TestUserLayerMayNarrowWithinACompiledRoot(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
`)},
	))
	require.NoErrorf(t, err, "narrowing includes within a compiled root must be allowed: %v", err)
	for _, s := range eff.Sources {
		if s.ID == "claude-code-transcripts" {
			assert.Truef(t, len(s.Include) == 1 && s.Include[0] == "projects/**/*.jsonl", "include not applied: %v", s.Include)
		}
	}
}

// A config whose include glob reaches a compiled-deny path is rejected and reported, not applied.
func TestIncludeReachingAgentCredentialsIsRejected(t *testing.T) {
	home := fakeHome(t)
	mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), `{"accessToken":"secret"}`)

	_, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    include: ["**"]
`)},
	))
	require.Error(t, err, "an include glob reaching .credentials.json must be rejected")
	assert.Containsf(t, err.Error(), "deny", "the refusal should name the deny list, got: %v", err)
}

func TestDenyListMatchesCredentialShapes(t *testing.T) {
	home := t.TempDir()
	d := sources.New(home)

	denied := []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "nested", "deeper", "key"),
		filepath.Join(home, ".claude", ".credentials.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".codex", "auth.json"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, "work", "project", ".env"),
		filepath.Join(home, "work", "project", ".env.local"),
		filepath.Join(home, "work", "certs", "server.pem"),
		filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
		filepath.Join(home, ".config", "gh", "hosts.yml"),
	}
	for _, p := range denied {
		if ok, _ := d.Match(p); !ok {
			t.Errorf("must be denied: %s", p)
		}
	}

	allowed := []string{
		filepath.Join(home, ".claude", "projects", "proj", "s.jsonl"),
		filepath.Join(home, ".claude", "CLAUDE.md"),
		filepath.Join(home, ".codex", "sessions", "2026", "r.jsonl"),
		filepath.Join(home, "work", "project", "src", "db.go"),
	}
	for _, p := range allowed {
		if ok, pat := d.Match(p); ok {
			t.Errorf("must not be denied: %s (matched %q)", p, pat)
		}
	}
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

// A root that does not look like the store it claims to be is not that store.
func TestRequireSubdirRefusesAWrongShapedRoot(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude"))
	// No projects/ dir: the root exists but is the wrong shape.

	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	for _, s := range eff.Sources {
		if s.ID == "claude-code-transcripts" {
			assert.Equalf(t, "", s.Root, "a root with no projects/ dir must not resolve, got %q", s.Root)
			assert.Containsf(t, s.RootUnresolvedReason, "projects", "the reason should name the missing subdir, got %q", s.RootUnresolvedReason)
		}
	}
}

// The daemon resolves roots once and then ticks for days. Claude Code creates projects/ on its
// first run, which is routinely after the shipper started: without a refresh that install reports
// agent_absent forever, looking healthy while collecting nothing.
func TestARootThatAppearsAfterStartupIsPickedUp(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude")) // present, but not yet the right shape

	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	require.Equal(t, "", sourceByID(t, eff, "claude-code-transcripts").Root)

	// The agent runs for the first time.
	mustWrite(t, filepath.Join(home, ".claude", "projects", "-Users-jane-api", "s.jsonl"), "{}\n")

	found := config.RefreshAbsentRoots(eff, env(home, nil))
	assert.Truef(t, slices.Contains(found, "claude-code-transcripts"), "the newly resolved source must be reported so the tick can announce it, got %v", found)
	src := sourceByID(t, eff, "claude-code-transcripts")
	assert.Equalf(t, filepath.Join(home, ".claude"), src.Root, "root should now resolve, got %q (%s)", src.Root, src.RootUnresolvedReason)
	assert.Equalf(t, "", src.RootUnresolvedReason, "a resolved root must carry no absence reason, got %q", src.RootUnresolvedReason)
}

// A root already in use keys the fingerprints that decide what has been shipped. Re-picking it
// could move collection to a different directory mid-run, so a refresh only fills in the gaps.
func TestRefreshLeavesAnAlreadyResolvedRootAlone(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	before := sourceByID(t, eff, "claude-code-transcripts").Root
	require.NotEqual(t, "", before, "precondition: the root must resolve from a fake home")

	if found := config.RefreshAbsentRoots(eff, env(home, nil)); slices.Contains(found, "claude-code-transcripts") {
		t.Errorf("a source that already resolved must not be reported as newly found, got %v", found)
	}
	assert.Equal(t, sourceByID(t, eff, "claude-code-transcripts").Root, before)
}

// An agent that is still absent keeps an accurate reason, and the refresh reports nothing: doctor
// and the heartbeat read this string, so a stale one is what made the outage unreadable.
func TestRefreshKeepsTheReasonCurrentWhileTheAgentStaysAbsent(t *testing.T) {
	home := t.TempDir()
	mustMkdir(t, filepath.Join(home, ".claude"))

	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	assert.Len(t, config.RefreshAbsentRoots(eff, env(home, nil)), 0)
	src := sourceByID(t, eff, "claude-code-transcripts")
	assert.Equalf(t, "", src.Root, "the root must stay unresolved, got %q", src.Root)
	assert.Containsf(t, src.RootUnresolvedReason, "projects", "the reason should still name the missing subdir, got %q", src.RootUnresolvedReason)
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
	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	for _, s := range eff.Sources {
		assert.Truef(t, s.ID != "claude-code-transcripts" || s.Root != "", "with $CLAUDE_CONFIG_DIR unset, ~/.claude must still resolve: %s", s.RootUnresolvedReason)
	}
}

func TestRelativeExpansionIsRefused(t *testing.T) {
	home := fakeHome(t)
	e := env(home, map[string]string{"CLAUDE_CONFIG_DIR": "relative/path"})
	if _, err := e.ExpandRoot("$CLAUDE_CONFIG_DIR"); err == nil {
		t.Fatal("a root expanding to a relative path must be refused")
	}
}

// A root that does not exist must not resolve: agent_absent has to stay separable from root_present_no_match.
func TestNonExistentRootDoesNotResolve(t *testing.T) {
	home := fakeHome(t) // has ~/.claude, deliberately no ~/.cursor

	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
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

	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	for _, s := range eff.Sources {
		assert.Truef(t, s.Family != "claude-code" || s.Root == "", "%s: a regular file must not resolve as a root, got %q", s.ID, s.Root)
	}
}
