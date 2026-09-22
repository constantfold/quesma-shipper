package sources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

// A remote carrying a live credential must normalise to host/org/repo with the token absent from every output.
func TestRemoteNormalisationStripsUserinfo(t *testing.T) {
	for _, c := range []struct{ raw, hostPath, project string }{
		{"https://user:" + fixtureToken + "@github.com/org/repo.git", "github.com/org/repo", "repo"},
		{"https://jane@github.com/org/repo", "github.com/org/repo", "repo"},
		{"https://github.com/org/repo.git", "github.com/org/repo", "repo"},
		{"git@github.com:org/repo.git", "github.com/org/repo", "repo"},
		{"ssh://git@github.com/org/repo.git", "github.com/org/repo", "repo"},
		{"ssh://git@github.com:2222/org/repo.git", "github.com/org/repo", "repo"},
		{"https://gitlab.com/group/sub/repo.git", "gitlab.com/group/sub/repo", "repo"},
		{"https://GitHub.com/Org/Repo.git", "github.com/Org/Repo", "Repo"},
		// Local and empty remotes are refused.
		{"/Users/jane/src/thing", "", ""},
		{"file:///Users/jane/src/thing", "", ""},
		{"", "", ""},
	} {
		hostPath, project, err := NormaliseRemote(c.raw)
		assert.Equal(t, c.hostPath == "", err != nil, c.raw)
		assert.Equal(t, c.hostPath, hostPath, c.raw)
		assert.Equal(t, c.project, project, c.raw)
	}
}

func sidecarSource() Resolved {
	return Resolved{
		Source: Source{
			ID: "project-map", Family: "project-map", Gather: "sidecar", ArtifactClass: "context", Emit: "git_project_map",
			CWDProbe: &CWDProbe{From: []string{"claude-code-transcripts"}, Fields: []string{"cwd", "payload.cwd"}, ScanBytes: 65536},
			GitRead:  &GitRead{WalkUp: true, FollowGitdirFile: true, Take: []string{"remote.*.url"}},
		},
		Enabled: true,
	}
}

func sidecarBody(t *testing.T, home string, input, sidecar Resolved) string {
	t.Helper()
	d, err := Discover(Request{Source: sidecar, All: []Resolved{input, sidecar}, Deny: New(home), StateDir: t.TempDir(), Username: "jane"})
	require.NoError(t, err)
	require.Equal(t, Collected, d.Health, d.Reason)
	require.Len(t, d.Candidates, 1, "one inventory per source")
	body, err := os.ReadFile(d.Candidates[0].Path)
	require.NoError(t, err)
	return string(body)
}

func session(cwd string) string {
	return `{"type":"user","uuid":"u1","cwd":` + strconv.Quote(cwd) + `,"message":{"content":[]}}` + "\n"
}

// The full path: a transcript names a cwd inside a checkout whose remote carries a token.
func TestSidecarEmitsMappingWithoutTheToken(t *testing.T) {
	home := t.TempDir()
	checkout := filepath.Join(home, "work", "api")
	writeFile(t, filepath.Join(checkout, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"+
		"\turl = https://jane:"+fixtureToken+"@github.com/acme/api.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[credential]\n\thelper = osxkeychain\n")
	agentRoot := filepath.Join(home, ".claude")
	writeFile(t, filepath.Join(agentRoot, "projects", "-Users-jane-work-api", "s1.jsonl"), session(checkout))

	body := sidecarBody(t, home, globSource(agentRoot, "projects/**/*.jsonl"), sidecarSource())
	require.NotContains(t, body, fixtureToken)
	assert.NotContains(t, body, "jane:")
	var rec ProjectRecord
	require.NoError(t, json.Unmarshal([]byte(body), &rec))
	assert.Equal(t, "github.com/acme/api", rec.Remote)
	assert.Equal(t, "api", rec.Project)
	// Placeholdered, and the join still holds: a shipped manifest's native_path carries the same rewritten username.
	assert.Equal(t, "-Users-__USER__-work-api", rec.ProjectDir)
	assert.NotContains(t, rec.CWD, "jane")
}

// Each case lays out a checkout under home and returns the session line. A missing remote must say why.
func TestSidecarResolvesTheRemote(t *testing.T) {
	const origin = "[remote \"origin\"]\n\turl = https://github.com/acme/api.git\n"
	worktree := func(withCommondir bool) func(*testing.T, string) string {
		// A worktree's .git is a FILE holding a gitdir: pointer; its commondir, when present, names the dir with the config.
		return func(t *testing.T, home string) string {
			gitDir := filepath.Join(home, "repos", "api", ".git", "worktrees", "wt")
			configDir := gitDir
			if withCommondir {
				configDir = filepath.Join(home, "repos", "api", ".git")
				writeFile(t, filepath.Join(gitDir, "commondir"), "../..\n")
			}
			writeFile(t, filepath.Join(configDir, "config"), origin)
			wt := filepath.Join(home, "work", "wt")
			writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitDir+"\n")
			return session(wt)
		}
	}
	for _, tc := range []struct {
		name, remote, gaveUp string
		setup                func(t *testing.T, home string) string
	}{
		{"walks up to the repository root", "github.com/acme/api", "", func(t *testing.T, home string) string {
			writeFile(t, filepath.Join(home, "work", "api", ".git", "config"), origin)
			deep := filepath.Join(home, "work", "api", "src", "internal", "db")
			require.NoError(t, os.MkdirAll(deep, 0o700))
			return session(deep)
		}},
		{"nested cwd field", "github.com/acme/api", "", func(t *testing.T, home string) string {
			repo := filepath.Join(home, "work", "api")
			writeFile(t, filepath.Join(repo, ".git", "config"), origin)
			return `{"timestamp":"t","type":"session_meta","payload":{"cwd":` + strconv.Quote(repo) + `}}` + "\n"
		}},
		{"worktree with commondir", "github.com/acme/api", "", worktree(true)},
		{"worktree without commondir", "github.com/acme/api", "", worktree(false)},
		{"no repository", "", ".git", func(t *testing.T, home string) string {
			dir := filepath.Join(home, "scratch")
			require.NoError(t, os.MkdirAll(dir, 0o700))
			return session(dir)
		}},
		// The trajectory outlives the checkout.
		{"vanished cwd", "", "", func(t *testing.T, home string) string {
			gone := filepath.Join(home, "deleted", "long", "ago")
			return session(gone)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			body := tc.setup(t, home)
			agentRoot := filepath.Join(home, ".claude")
			writeFile(t, filepath.Join(agentRoot, "projects", "-Users-jane-work", "s1.jsonl"), body)
			var rec ProjectRecord
			require.NoError(t, json.Unmarshal([]byte(sidecarBody(t, home, globSource(agentRoot, "projects/**/*.jsonl"), sidecarSource())), &rec))
			assert.Equal(t, tc.remote, rec.Remote, rec.GaveUp)
			if tc.remote == "" {
				assert.NotEmpty(t, rec.GaveUp, "a gap must be explained rather than merely empty")
				assert.Contains(t, rec.GaveUp, tc.gaveUp)
			}
		})
	}
}

// A path with no projects/<encoded-cwd> segment produces no record: a bogus join key is worse than a missing one.
func TestSidecarEmitsNoRecordWithoutAProjectDirSegment(t *testing.T) {
	home := t.TempDir()
	repo := filepath.Join(home, "work", "api")
	writeFile(t, filepath.Join(repo, ".git", "config"), "[remote \"origin\"]\n\turl = https://github.com/acme/api.git\n")
	codexRoot := filepath.Join(home, ".codex")
	writeFile(t, filepath.Join(codexRoot, "sessions", "2026", "07", "30", "rollout-x.jsonl"),
		`{"timestamp":"t","type":"session_meta","payload":{"cwd":`+strconv.Quote(repo)+`}}`+"\n")

	rollouts := globSource(codexRoot, "sessions/**/*.jsonl")
	rollouts.ID = "codex-rollouts"
	sc := sidecarSource()
	sc.CWDProbe.From = []string{"codex-rollouts"}
	assert.Empty(t, strings.TrimSpace(sidecarBody(t, home, rollouts, sc)))
}
