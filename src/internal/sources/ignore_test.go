package sources

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testProbe() *CWDProbe {
	return &CWDProbe{From: []string{"claude-code-transcripts", "codex-rollouts"}, Fields: []string{"cwd", "payload.cwd"}, ScanBytes: 64 << 10}
}

func testGitRead() *GitRead { return &GitRead{WalkUp: true, FollowGitdirFile: true} }

func claudeSource(root string) Resolved {
	return Resolved{Source: Source{ID: "claude-code-transcripts", Include: []string{"projects/**/*.jsonl"}}, Root: root, Enabled: true}
}

// writeSession writes a session under root whose second line names cwd, or none when cwd is empty.
func writeSession(t *testing.T, root, rel, cwd string) Candidate {
	t.Helper()
	body := "{}\n"
	if cwd != "" {
		body = `{"type":"summary"}` + "\n" + `{"type":"user","cwd":` + strconv.Quote(cwd) + `}` + "\n"
	}
	writeFile(t, filepath.Join(root, rel), body)
	return Candidate{Path: filepath.Join(root, rel), RelPath: rel}
}

func repoDir(t *testing.T, home, rel string, marked bool) string {
	t.Helper()
	dir := filepath.Join(home, rel)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	if marked {
		writeFile(t, MarkerPath(dir), "")
	}
	return dir
}

func gitRepo(t *testing.T, home, rel string) string {
	t.Helper()
	dir := repoDir(t, home, rel, false)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	return dir
}

// writeWorktree lays out a linked worktree as git does: pointer file, admin dir under the main .git, commondir.
func writeWorktree(t *testing.T, main, at, name string) string {
	t.Helper()
	adminDir := filepath.Join(main, ".git", "worktrees", name)
	writeFile(t, filepath.Join(adminDir, "commondir"), "../..\n")
	wt := filepath.Join(at, name)
	writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+adminDir+"\n")
	return wt
}

func TestRepoNameIsTheLastSegment(t *testing.T) {
	assert.Equal(t, "client-acme", RepoName("/Users/jane/work/client-acme"))
	assert.Empty(t, RepoName(""))
}

// A marker drops its repository's sessions, and a sibling with no cwd inherits its project directory's answer.
func TestMarkerDropsARepositorysSessions(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	acme := repoDir(t, home, "work/acme", true)
	keeper := repoDir(t, home, "work/keeper", false)
	f := newRepoFilter(testProbe(), nil, home)
	codex := Resolved{Source: Source{ID: "codex-rollouts"}, Root: root}

	for _, tc := range []struct {
		src      Resolved
		rel, cwd string
		want     bool
	}{
		{claudeSource(root), "projects/p-acme/a.jsonl", acme, true},
		{claudeSource(root), "projects/p-acme/b.jsonl", "", true},
		{claudeSource(root), "projects/p-keeper/c.jsonl", keeper, false},
		{claudeSource(root), "projects/p-orphan/d.jsonl", "", false},
		{codex, "sessions/2026/07/20/rollout-a.jsonl", acme, true},
		{codex, "sessions/2026/07/20/rollout-b.jsonl", keeper, false},
	} {
		assert.Equal(t, tc.want, f.Match(tc.src, writeSession(t, root, tc.rel, tc.cwd)), tc.rel)
	}
}

// A catalog without a probe attributes nothing, and a source the probe does not name is never read.
func TestRepoFilterScope(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	c := writeSession(t, root, "a.jsonl", repoDir(t, home, "work/acme", true))
	assert.False(t, newRepoFilter(nil, nil, home).Match(Resolved{}, c))
	assert.False(t, newRepoFilter(testProbe(), nil, home).Match(Resolved{Source: Source{ID: "cursor-transcripts"}, Root: root}, c))
}

// Only attribution is memoised, never the marker: one created or removed while the process runs bites on the next look.
func TestAMarkerCreatedLaterIsSeen(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	acme := repoDir(t, home, "work/acme", false)
	c := writeSession(t, root, "projects/p-acme/a.jsonl", acme)
	f := newRepoFilter(testProbe(), nil, home)

	require.False(t, f.Match(claudeSource(root), c), "nothing is marked yet")
	require.NoError(t, f.Untrack(acme))
	assert.True(t, f.Match(claudeSource(root), c), "a marker created after the first look must be seen")
	require.NoError(t, f.Track(acme))
	assert.False(t, f.Match(claudeSource(root), c), "a removed marker must stop matching")
	assert.NoError(t, f.Track(acme))
}

// A worktree session belongs to the main checkout; a cwd outside git, or with no git rules, keeps its own directory.
func TestRepoDirIsTheMainWorktree(t *testing.T) {
	catalog, err := Load()
	require.NoError(t, err)
	home, root := t.TempDir(), t.TempDir()
	repo := gitRepo(t, home, "work/acme")
	nested := writeWorktree(t, repo, filepath.Join(repo, ".claude", "worktrees"), "woolly-kindling")
	elsewhere := writeWorktree(t, repo, filepath.Join(home, "wt"), "stray")
	plain := repoDir(t, home, "notes", false)

	f := newRepoFilter(testProbe(), testGitRead(), home)
	for i, tc := range []struct{ cwd, want string }{
		{repo, repo},
		{nested, repo},
		{filepath.Join(nested, "internal", "db"), repo},
		{elsewhere, repo},
		{filepath.Join(repo, ".claude", "worktrees", "deleted"), repo},
		{plain, plain},
	} {
		c := writeSession(t, root, fmt.Sprintf("projects/p-%d/s.jsonl", i), tc.cwd)
		assert.Equal(t, tc.want, f.RepoDir(claudeSource(root), c), tc.cwd)
		assert.Equal(t, tc.want, catalog.RepoFilter().RepoDir(claudeSource(root), c), tc.cwd)
	}
	c := writeSession(t, root, "projects/p-nogit/s.jsonl", nested)
	assert.Equal(t, nested, newRepoFilter(testProbe(), nil, home).RepoDir(claudeSource(root), c))
}

// Markers govern a checkout, one worktree, or a plain directory according to their placement.
func TestWorktreeMarkerScope(t *testing.T) {
	type session struct {
		cwd  string
		want bool
	}
	for name, setup := range map[string]func(*testing.T, string) []session{
		"repository covers its worktrees": func(t *testing.T, home string) []session {
			acme := gitRepo(t, home, "work/acme")
			writeFile(t, MarkerPath(acme), "")
			keeper := gitRepo(t, home, "work/keeper")
			return []session{
				{writeWorktree(t, acme, filepath.Join(acme, ".claude", "worktrees"), "nested"), true},
				{writeWorktree(t, acme, filepath.Join(home, "wt"), "stray"), true},
				{filepath.Join(acme, ".claude", "worktrees", "deleted"), true},
				{writeWorktree(t, keeper, filepath.Join(home, "wt"), "keeper-wt"), false},
			}
		},
		"worktree covers only itself": func(t *testing.T, home string) []session {
			repo := gitRepo(t, home, "work/acme")
			marked := writeWorktree(t, repo, filepath.Join(home, "wt"), "marked")
			writeFile(t, MarkerPath(marked), "")
			open := writeWorktree(t, repo, filepath.Join(home, "wt"), "open")
			return []session{{marked, true}, {open, false}, {repo, false}}
		},
		"ancestor covers plain directories only": func(t *testing.T, home string) []session {
			writeFile(t, MarkerPath(filepath.Join(home, "clients")), "")
			repo := gitRepo(t, home, "clients/acme")
			wt := writeWorktree(t, repo, filepath.Join(home, "clients", "wt"), "stray")
			return []session{{repo, false}, {wt, false}, {repoDir(t, home, "clients/notes", false), true}}
		},
		// A marker above home must not turn the whole machine off by accident.
		"ancestors count up to home only": func(t *testing.T, home string) []session {
			writeFile(t, MarkerPath(filepath.Dir(home)), "")
			repoDir(t, home, "work", true)
			return []session{{repoDir(t, home, "work/acme/sub", false), true}, {repoDir(t, home, "other/repo", false), false}}
		},
		// A checkout at home (dotfiles) must not claim every directory under it.
		"a marker at home stays out of checkouts": func(t *testing.T, home string) []session {
			require.NoError(t, os.MkdirAll(filepath.Join(home, ".git"), 0o700))
			writeFile(t, MarkerPath(home), "")
			return []session{{repoDir(t, home, "notes", false), true}, {gitRepo(t, home, "work/acme"), false}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			f := newRepoFilter(testProbe(), testGitRead(), home)
			for i, tc := range setup(t, home) {
				c := writeSession(t, root, fmt.Sprintf("projects/p-%d/s.jsonl", i), tc.cwd)
				assert.Equal(t, tc.want, f.Match(claudeSource(root), c), tc.cwd)
				_, marked := f.Marker(tc.cwd)
				assert.Equal(t, tc.want, marked, tc.cwd)
			}
		})
	}
}

func TestACheckoutAtHomeDoesNotClaimEverything(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".git"), 0o700))
	notes := repoDir(t, home, "notes", false)
	acme := gitRepo(t, home, "work/acme")
	f := newRepoFilter(testProbe(), testGitRead(), home)
	for i, dir := range []string{notes, home, acme} {
		c := writeSession(t, root, fmt.Sprintf("projects/p-%d/s.jsonl", i), dir)
		assert.Equal(t, dir, f.RepoDir(claudeSource(root), c))
	}
}

// A source emptied by markers says so instead of reporting drift, and names no oversized file of an untracked repository.
func TestDiscoveryDistinguishesIgnoredFromDrift(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	repo := gitRepo(t, home, "work/acme")
	writeFile(t, MarkerPath(repo), "")
	writeSession(t, root, "projects/p-acme/a.jsonl", repo)
	writeSession(t, root, "projects/p-acme/b.jsonl", "")
	writeSession(t, root, "projects/p-wt/c.jsonl", writeWorktree(t, repo, filepath.Join(home, "wt"), "stray"))
	src := claudeSource(root)
	src.MaxFileBytes = 4

	d, err := discoverByGlob(Request{Source: src, Deny: New(t.TempDir()), Ignore: newRepoFilter(testProbe(), testGitRead(), home)})
	require.NoError(t, err)
	assert.Empty(t, d.Candidates)
	assert.Empty(t, d.Oversize)
	assert.True(t, d.Ignored)
	assert.Equal(t, ignoredReason, d.Reason)
}
