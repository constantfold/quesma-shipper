package sources

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testProbe() *CWDProbe {
	return &CWDProbe{From: []string{"claude-code-transcripts", "codex-rollouts"}, Fields: []string{"cwd", "payload.cwd"}, ScanBytes: 64 << 10}
}

func writeSession(t *testing.T, path, cwd string) {
	t.Helper()
	body := "{}\n"
	if cwd != "" {
		body = `{"type":"summary"}` + "\n" + `{"type":"user","cwd":` + strconv.Quote(cwd) + `}` + "\n"
	}
	writeFile(t, path, body)
}

func candidateFor(root, rel string) Candidate {
	return Candidate{Path: filepath.Join(root, rel), RelPath: rel}
}

// repoDir makes a repository directory under home, optionally carrying the marker.
func repoDir(t *testing.T, home, rel string, marked bool) string {
	t.Helper()
	dir := filepath.Join(home, rel)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	if marked {
		require.NoError(t, os.WriteFile(filepath.Join(dir, notrajectories), nil, 0o600))
	}
	return dir
}

func TestRepoNameIsTheLastSegment(t *testing.T) {
	for _, tc := range []struct{ cwd, want string }{{"/Users/jane/work/client-acme", "client-acme"}, {"", ""}} {
		assert.Equal(t, RepoName(tc.cwd), tc.want)
	}
}

// A marker in the repository drops its sessions; a sibling with no cwd inherits its
// project directory's answer; an unmarked repository and an unattributable file ship.
func TestMarkerDropsARepositorysSessions(t *testing.T) {
	home := t.TempDir()
	acme := repoDir(t, home, "work/acme", true)
	keeper := repoDir(t, home, "work/keeper", false)
	root := t.TempDir()
	writeSession(t, filepath.Join(root, "projects/p-acme/a.jsonl"), acme)
	writeSession(t, filepath.Join(root, "projects/p-acme/b.jsonl"), "")
	writeSession(t, filepath.Join(root, "projects/p-keeper/c.jsonl"), keeper)
	writeSession(t, filepath.Join(root, "projects/p-orphan/d.jsonl"), "")
	src := Resolved{Source: Source{ID: "claude-code-transcripts"}, Root: root}
	f := newRepoFilter(testProbe(), nil, home)

	for _, tc := range []struct {
		rel  string
		want bool
	}{
		{"projects/p-acme/a.jsonl", true},
		{"projects/p-acme/b.jsonl", true},
		{"projects/p-keeper/c.jsonl", false},
		{"projects/p-orphan/d.jsonl", false},
	} {
		assert.Equal(t, f.Match(src, candidateFor(root, tc.rel)), tc.want)
	}
}

// A marker covers everything under it, and the walk stops at home: a marker above home
// must not turn the whole machine off by accident.
func TestMarkerCoversDescendantsAndStopsAtHome(t *testing.T) {
	outer := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outer, notrajectories), nil, 0o600))
	home := filepath.Join(outer, "home")
	repoDir(t, home, "work", true)
	inside := repoDir(t, home, "work/acme/sub", false)
	unmarked := repoDir(t, home, "other/repo", false)

	f := newRepoFilter(testProbe(), nil, home)
	if _, ok := f.Marker(inside); !ok {
		t.Error("an ancestor's marker must cover a nested working directory")
	}
	if _, ok := f.Marker(unmarked); ok {
		t.Error("a marker above home must not count")
	}
}

// Codex files rollouts under a date directory, so attribution is per file there: one
// session must not be attributed to another's repository.
func TestMarkersDoNotLeakAcrossADateDirectory(t *testing.T) {
	home := t.TempDir()
	acme := repoDir(t, home, "work/acme", true)
	keeper := repoDir(t, home, "work/keeper", false)
	root := t.TempDir()
	writeSession(t, filepath.Join(root, "sessions/2026/07/20/rollout-a.jsonl"), acme)
	writeSession(t, filepath.Join(root, "sessions/2026/07/20/rollout-b.jsonl"), keeper)
	src := Resolved{Source: Source{ID: "codex-rollouts"}, Root: root}
	f := newRepoFilter(testProbe(), nil, home)
	assert.True(t, f.Match(src, candidateFor(root, "sessions/2026/07/20/rollout-a.jsonl")), "the marked repository's rollout must match")
	assert.True(t, !f.Match(src, candidateFor(root, "sessions/2026/07/20/rollout-b.jsonl")), "a rollout from another repository must not match")
}

// A catalog without a probe attributes nothing, and a source the probe does not name is
// never read.
func TestRepoFilterScope(t *testing.T) {
	home := t.TempDir()
	acme := repoDir(t, home, "work/acme", true)
	root := t.TempDir()
	writeSession(t, filepath.Join(root, "a.jsonl"), acme)
	c := candidateFor(root, "a.jsonl")
	require.True(t, !newRepoFilter(nil, nil, home).Match(Resolved{}, c) && !newRepoFilter(testProbe(), nil, home).Match(Resolved{Source: Source{ID: "cursor-transcripts"}, Root: root}, c), "matched with nothing to match on")
}

// A marker created while the process runs bites on the next look: only attribution is
// memoised, never the marker itself.
func TestAMarkerCreatedLaterIsSeen(t *testing.T) {
	home := t.TempDir()
	acme := repoDir(t, home, "work/acme", false)
	root := t.TempDir()
	writeSession(t, filepath.Join(root, "projects/p-acme/a.jsonl"), acme)
	src := Resolved{Source: Source{ID: "claude-code-transcripts"}, Root: root}
	f := newRepoFilter(testProbe(), nil, home)
	c := candidateFor(root, "projects/p-acme/a.jsonl")

	require.True(t, !f.Match(src, c), "nothing is marked yet")
	require.NoError(t, f.Untrack(acme))
	assert.True(t, f.Match(src, c), "a marker created after the first look must be seen")
	require.NoError(t, f.Track(acme))
	assert.True(t, !f.Match(src, c), "a removed marker must stop matching")
	assert.NoError(t, f.Track(acme))
}

func testGitRead() *GitRead {
	return &GitRead{WalkUp: true, FollowGitdirFile: true}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// gitRepo makes a checkout with a real .git directory.
func gitRepo(t *testing.T, home, rel string) string {
	t.Helper()
	dir := repoDir(t, home, rel, false)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o700))
	return dir
}

// writeWorktree lays out a linked worktree the way git does: the pointer file in the
// worktree, the per-worktree admin dir under the main .git, and commondir pointing back.
func writeWorktree(t *testing.T, main, at, name string) string {
	t.Helper()
	adminDir := filepath.Join(main, ".git", "worktrees", name)
	writeFile(t, filepath.Join(adminDir, "commondir"), "../..\n")
	wt := filepath.Join(at, name)
	writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+adminDir+"\n")
	return wt
}

// A session run in a worktree belongs to the repository's main checkout, not to the
// worktree directory's disposable name; a cwd outside git keeps its own directory.
func TestRepoDirIsTheMainWorktree(t *testing.T) {
	home := t.TempDir()
	repo := gitRepo(t, home, "work/acme")
	nested := writeWorktree(t, repo, filepath.Join(repo, ".claude", "worktrees"), "woolly-kindling")
	elsewhere := writeWorktree(t, repo, filepath.Join(home, "wt"), "stray")
	gone := filepath.Join(repo, ".claude", "worktrees", "deleted")
	plain := repoDir(t, home, "notes", false)

	root := t.TempDir()
	src := Resolved{Source: Source{ID: "claude-code-transcripts"}, Root: root}
	f := newRepoFilter(testProbe(), testGitRead(), home)
	for i, tc := range []struct{ cwd, want string }{
		{repo, repo},
		{nested, repo},
		{filepath.Join(nested, "internal", "db"), repo},
		{elsewhere, repo},
		{gone, repo},
		{plain, plain},
	} {
		rel := fmt.Sprintf("projects/p-%d/s.jsonl", i)
		writeSession(t, filepath.Join(root, rel), tc.cwd)
		assert.Equal(t, f.RepoDir(src, candidateFor(root, rel)), tc.want)
	}

	assert.Equal(t, newRepoFilter(testProbe(), nil, home).RepoDir(src, candidateFor(root, "projects/p-1/s.jsonl")), nested)
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
			writeFile(t, filepath.Join(acme, notrajectories), "")
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
			writeFile(t, filepath.Join(marked, notrajectories), "")
			open := writeWorktree(t, repo, filepath.Join(home, "wt"), "open")
			return []session{{marked, true}, {open, false}, {repo, false}}
		},
		"ancestor covers plain directories only": func(t *testing.T, home string) []session {
			writeFile(t, filepath.Join(home, "clients", notrajectories), "")
			repo := gitRepo(t, home, "clients/acme")
			wt := writeWorktree(t, repo, filepath.Join(home, "clients", "wt"), "stray")
			plain := repoDir(t, home, "clients/notes", false)
			return []session{{repo, false}, {wt, false}, {plain, true}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			f := newRepoFilter(testProbe(), testGitRead(), home)
			src := Resolved{Source: Source{ID: "claude-code-transcripts"}, Root: root}
			sessions := setup(t, home)
			for i, tc := range sessions {
				rel := fmt.Sprintf("projects/p-%d/s.jsonl", i)
				writeSession(t, filepath.Join(root, rel), tc.cwd)
				assert.Equal(t, tc.want, f.Match(src, candidateFor(root, rel)), tc.cwd)
			}
			for _, tc := range sessions {
				_, marked := f.Marker(tc.cwd)
				assert.Equal(t, tc.want, marked, tc.cwd)
			}
		})
	}
}

// Worktrees inherit repository attribution and markers through both configured and catalog filters.
func TestWorktreeAttributionAndTracking(t *testing.T) {
	catalog, err := Load()
	require.NoError(t, err)
	for _, parent := range []string{"work/acme/.claude/worktrees", "wt"} {
		t.Run(parent, func(t *testing.T) {
			home := t.TempDir()
			repo := gitRepo(t, home, "work/acme")
			wt := writeWorktree(t, repo, filepath.Join(home, parent), "stray")
			root := t.TempDir()
			c := candidateFor(root, "projects/p-wt/s.jsonl")
			writeSession(t, c.Path, wt)
			src := Resolved{Source: Source{ID: "claude-code-transcripts", Include: []string{"projects/**/*.jsonl"}}, Root: root, Enabled: true}
			f := newRepoFilter(testProbe(), testGitRead(), home)
			assert.Equal(t, repo, catalog.RepoFilter().RepoDir(src, c))
			marker, marked := f.Marker(wt)
			assert.Empty(t, marker)
			assert.False(t, marked)

			markerPath := filepath.Join(repo, notrajectories)
			writeFile(t, markerPath, "")
			marker, marked = f.Marker(wt)
			assert.Equal(t, markerPath, marker)
			assert.True(t, marked)
			for _, filter := range []*RepoFilter{f, newRepoFilter(testProbe(), testGitRead(), home)} {
				d, err := discoverByGlob(Request{Source: src, Deny: New(t.TempDir()), Ignore: filter})
				require.NoError(t, err)
				assert.Empty(t, d.Candidates)
				assert.True(t, d.Ignored)
			}
			require.NoError(t, f.Track(repo))
			assert.False(t, f.Match(src, c), "removing the repository marker resumes its worktrees")
		})
	}
}

// A source emptied by the markers says so, and is not the drift state; an oversized file
// in an untracked repository is not reported by name either.
func TestDiscoveryDistinguishesIgnoredFromDrift(t *testing.T) {
	home := t.TempDir()
	acme := repoDir(t, home, "work/acme", true)
	root := t.TempDir()
	writeSession(t, filepath.Join(root, "projects/p-acme/a.jsonl"), acme)
	writeSession(t, filepath.Join(root, "projects/p-acme/b.jsonl"), "")
	d, err := discoverByGlob(Request{
		Source: Resolved{Source: Source{ID: "claude-code-transcripts", Include: []string{"projects/**/*.jsonl"}, MaxFileBytes: 4}, Root: root, Enabled: true},
		Deny:   New(t.TempDir()),
		Ignore: newRepoFilter(testProbe(), nil, home),
	})
	require.NoError(t, err)
	assert.Truef(t, len(d.Candidates) == 0 && len(d.Oversize) == 0 && d.Ignored && strings.Contains(d.Reason, "not tracking"), "want an empty, deliberately ignored source; got %d candidates, %d oversize, ignored=%v, reason %q", len(d.Candidates), len(d.Oversize), d.Ignored, d.Reason)
}

func TestACheckoutAtHomeDoesNotClaimEverything(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".git"), 0o700))
	notes := repoDir(t, home, "notes", false)
	acme := gitRepo(t, home, "work/acme")

	root := t.TempDir()
	src := Resolved{Source: Source{ID: "claude-code-transcripts"}, Root: root}
	f := newRepoFilter(testProbe(), testGitRead(), home)
	for i, tc := range []struct{ cwd, want string }{{notes, notes}, {home, home}, {acme, acme}} {
		rel := fmt.Sprintf("projects/p-%d/s.jsonl", i)
		writeSession(t, filepath.Join(root, rel), tc.cwd)
		assert.Equal(t, f.RepoDir(src, candidateFor(root, rel)), tc.want)
	}
	writeFile(t, filepath.Join(home, notrajectories), "")
	if _, ok := f.Marker(notes); !ok {
		t.Error("a marker at home should cover a plain directory under it")
	}
	if _, ok := f.Marker(acme); ok {
		t.Error("a marker at home must not reach into a checkout")
	}
}
