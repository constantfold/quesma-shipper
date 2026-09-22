package sources

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func setMTime(t *testing.T, path string, at time.Time) {
	t.Helper()
	require.NoError(t, os.Chtimes(path, at, at))
}

// realTempDir resolves its own symlinks, so a test is not measuring /var -> /private/var.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

func globSource(root string, include ...string) Resolved {
	return Resolved{
		Source: Source{ID: "claude-code-transcripts", Family: "claude-code", Gather: "file_glob", Include: include,
			Sniff: &Sniff{Kind: "jsonl", MaxScanBytes: 65536}},
		Root:    root,
		Enabled: true,
	}
}

func discover(t *testing.T, src Resolved, deny *List) Discovery {
	t.Helper()
	d, err := Discover(Request{Source: src, Deny: deny, StateDir: t.TempDir()})
	require.NoError(t, err)
	return d
}

func relPaths(d Discovery) []string {
	var out []string
	for _, c := range d.Candidates {
		out = append(out, c.RelPath)
	}
	return out
}

func TestDiscoversMatchingFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "projects", "p", "a.jsonl"), `{"type":"user","version":"2.1.220"}`+"\n")
	writeFile(t, filepath.Join(root, "projects", "p", "b.jsonl"), `{"type":"user"}`+"\n")
	writeFile(t, filepath.Join(root, "projects", "p", "notes.md"), "# not matched\n")
	writeFile(t, filepath.Join(root, "projects", "node_modules", "skip.jsonl"), `{"a":2}`+"\n")

	src := globSource(root, "projects/**/*.jsonl")
	src.Exclude = []string{"**/node_modules/**"}
	d := discover(t, src, nil)

	assert.Equalf(t, formats.Collected, d.Health, "reason %q", d.Reason)
	assert.ElementsMatch(t, []string{"projects/p/a.jsonl", "projects/p/b.jsonl"}, relPaths(d))
	for _, c := range d.Candidates {
		assert.Truef(t, filepath.IsAbs(c.Path), "candidate path should be absolute: %q", c.Path)
	}
}

// agent_absent is expected silence and root_present_no_match probable drift; both must carry a reason for doctor.
func TestZeroCandidateHealthIsDistinguishedAndExplained(t *testing.T) {
	absent := globSource("", "projects/**/*.jsonl")
	absent.RootUnresolvedReason = "~/.claude does not exist"
	noMatch := t.TempDir()
	writeFile(t, filepath.Join(noMatch, "projects", "p", "notes.md"), "# nothing to collect\n")

	for _, tc := range []struct {
		src  Resolved
		want formats.HealthState
	}{
		{absent, formats.AgentAbsent},
		{globSource(noMatch, "projects/**/*.jsonl"), formats.RootPresentNoMatch},
		{globSource(t.TempDir(), "**/*.jsonl"), formats.RootPresentNoMatch},
	} {
		d := discover(t, tc.src, nil)
		assert.Equal(t, tc.want, d.Health)
		assert.NotEmpty(t, d.Reason)
		assert.Empty(t, d.Candidates)
	}
}

// Oldest first, since a bounded run must take the files closest to deletion; the version comes from the newest file.
func TestCandidatesAreOldestFirstAndVersionIsNewest(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "projects", "p", "old.jsonl")
	writeFile(t, old, `{"type":"user","version":"2.1.100"}`+"\n")
	setMTime(t, old, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	writeFile(t, filepath.Join(root, "projects", "p", "fresh.jsonl"), `{"type":"user","version":"2.1.245"}`+"\n")
	d := discover(t, globSource(root, "projects/**/*.jsonl"), nil)
	assert.Equal(t, []string{"projects/p/old.jsonl", "projects/p/fresh.jsonl"}, relPaths(d))
	assert.Equal(t, "2.1.245", d.AgentVersion)
}

// Shape drift blocks collection; empty sessions and both agents' version headers remain collectable.
func TestDiscoverySniffsStoreShapeAndVersion(t *testing.T) {
	zstd := &Sniff{Kind: "magic", MagicHex: "28b52ffd"}
	for _, tc := range []struct {
		name, path, body, version string
		spec                      *Sniff
		sniff                     formats.SniffResult
	}{
		{"binary store", "projects/p/a.jsonl", "\x00\x01\x02binary garbage\x00", "", nil, formats.SniffUnexpectedShape},
		{"sqlite replacing jsonl", "projects/p/a.jsonl", "SQLite format 3\x00\x04\x00\x01", "", nil, formats.SniffUnexpectedShape},
		{"empty file", "projects/p/a.jsonl", "", "", nil, formats.SniffEmpty},
		{"version on first line", "projects/p/a.jsonl", `{"type":"user","uuid":"u1","version":"2.1.220"}` + "\n", "2.1.220", nil, formats.SniffOK},
		{"version below first line", "projects/p/a.jsonl", `{"type":"summary","sessionId":"s"}` + "\n" +
			`{"type":"user","sessionId":"s"}` + "\n" + `{"type":"assistant","version":"2.1.245"}` + "\n", "2.1.245", nil, formats.SniffOK},
		{"codex nested version", "sessions/r.jsonl",
			`{"timestamp":"t","type":"session_meta","payload":{"cli_version":"0.144.1"}}` + "\n", "0.144.1", nil, formats.SniffOK},
		{"zstd magic", "sessions/r.jsonl.zst", "\x28\xb5\x2f\xfd\x00\x01\x02", "", zstd, formats.SniffOK},
		{"wrong magic", "sessions/r.jsonl.zst", "not zstd at all", "", zstd, formats.SniffUnexpectedShape},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, tc.path), tc.body)
			src := globSource(root, filepath.Dir(tc.path)+"/*")
			if tc.spec != nil {
				src.Gather, src.Sniff = "compressed_file", tc.spec
			}
			d := discover(t, src, nil)
			assert.Equal(t, tc.sniff, d.Sniff)
			assert.Equal(t, tc.version, d.AgentVersion)
			if tc.sniff == formats.SniffUnexpectedShape {
				assert.Equal(t, formats.MatchPresentUnreadable, d.Health)
				assert.Empty(t, d.Candidates)
			} else {
				assert.Equal(t, formats.Collected, d.Health)
				assert.Len(t, d.Candidates, 1)
			}
		})
	}
}

// The sniff asks about the STORE: one bad file fails per file, but a store where every sample fails is condemned.
func TestSniffSamplesTheStore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bad, good int
		collected bool
	}{
		{"one bad file", 1, 3, true},
		{"every file bad", 3, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for i := range tc.bad + tc.good {
				path := filepath.Join(root, "projects", "p", strings.Repeat(string(rune('0'+i)), 8)+".jsonl")
				if i < tc.bad {
					writeFile(t, path, "\x00\x00\x00 not json at all\n")
					setMTime(t, path, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
				} else {
					writeFile(t, path, `{"type":"user","uuid":"u1"}`+"\n")
				}
			}
			d := discover(t, globSource(root, "projects/**/*.jsonl"), nil)
			if tc.collected {
				assert.Equalf(t, formats.Collected, d.Health, "reason %s", d.Reason)
				assert.Len(t, d.Candidates, tc.bad+tc.good)
				assert.NotZero(t, d.SniffFailures, "the bad file should be counted even when the source is fine")
			} else {
				assert.NotEqual(t, formats.Collected, d.Health)
				assert.Empty(t, d.Candidates)
			}
		})
	}
}

// An oversized file is skipped AND counted, and does not stop the rest of the source.
func TestAnOversizedFileIsSkippedAndCounted(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "projects", "p", "small.jsonl"), `{"type":"user"}`+"\n")
	// Sparse: the cap is checked against the stat, so a file this size must never be read.
	f, err := os.Create(filepath.Join(root, "projects", "p", "big.jsonl"))
	require.NoError(t, err)
	require.NoError(t, f.Truncate(300<<20))
	require.NoError(t, f.Close())

	src := globSource(root, "projects/**/*.jsonl")
	src.MaxFileBytes = 256 << 20
	d := discover(t, src, nil)

	assert.Equal(t, []string{"projects/p/small.jsonl"}, relPaths(d))
	require.Len(t, d.Oversize, 1)
	assert.Greater(t, d.Oversize[0].Size, d.Oversize[0].Limit)
	assert.Equal(t, formats.Collected, d.Health)
}

// The walk does not follow symlinks, which pairs with O_NOFOLLOW at open time; neither is sufficient alone.
func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.jsonl"), `{"secret":true}`+"\n")
	writeFile(t, filepath.Join(root, "projects", "p", "real.jsonl"), `{"a":1}`+"\n")
	if err := os.Symlink(filepath.Join(outside, "secret.jsonl"), filepath.Join(root, "projects", "p", "linked.jsonl")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	d := discover(t, globSource(root, "projects/**/*.jsonl"), nil)
	assert.Equal(t, []string{"projects/p/real.jsonl"}, relPaths(d))
}

// The deny list is the read-time authority, since a credential file can appear after config validation.
// A denied tree is pruned, not walked; pruning follows only a whole-tree rule, so a directory named .env
// is walked; and a parent that links into a denied tree is still denied.
func TestDenyListAppliesAtDiscoveryTime(t *testing.T) {
	home := realTempDir(t)
	writeFile(t, filepath.Join(home, ".claude", "projects", "p", "a.jsonl"), `{"a":1}`+"\n")
	writeFile(t, filepath.Join(home, ".claude", ".credentials.json"), `{"accessToken":"secret"}`)
	writeFile(t, filepath.Join(home, "projects", ".env", "b.jsonl"), `{"b":2}`+"\n")
	writeFile(t, filepath.Join(home, "projects", "release.key", "c.jsonl"), `{"c":3}`+"\n")
	writeFile(t, filepath.Join(home, "projects", ".env", ".env"), "TOKEN=x\n")
	secret := filepath.Join(home, ".ssh")
	writeFile(t, filepath.Join(secret, "store", "leak.jsonl"), `{"token":"x"}`+"\n")
	if err := os.Symlink(secret, filepath.Join(home, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	linked := discover(t, globSource(filepath.Join(home, "link", "store"), "**"), New(home))
	assert.Empty(t, linked.Candidates, "a file inside the ssh store was offered for shipping")

	if os.Geteuid() != 0 {
		// Unreadable, so descending into it would also be counted and reported.
		require.NoError(t, os.Chmod(secret, 0o000))
		t.Cleanup(func() { _ = os.Chmod(secret, 0o700) })
	}
	// A glob wide enough to reach the credential files, as a hostile config would.
	d := discover(t, globSource(home, "**"), New(home))
	assert.ElementsMatch(t, []string{".claude/projects/p/a.jsonl", "projects/.env/b.jsonl", "projects/release.key/c.jsonl"}, relPaths(d))
	assert.Zerof(t, d.Unreadable, "the denied tree was opened: %s", d.UnreadableReason)
}

// A permission denial deep in a store must not abort the walk.
func TestUnreadableSubtreeDoesNotAbortTheWalk(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits do not apply")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "projects", "open", "a.jsonl"), `{"a":1}`+"\n")
	closed := filepath.Join(root, "projects", "closed")
	writeFile(t, filepath.Join(closed, "b.jsonl"), `{"a":2}`+"\n")
	require.NoError(t, os.Chmod(closed, 0o000))
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })

	d := discover(t, globSource(root, "projects/**/*.jsonl"), nil)
	assert.Equal(t, []string{"projects/open/a.jsonl"}, relPaths(d))
	assert.Equal(t, 1, d.Unreadable)
}

func TestOnlyCompiledGatherPrimitives(t *testing.T) {
	for gather, compiled := range map[string]bool{"acp": false, "cloud_pull": false, "sqlite_rows": false, "file_glob": true, "compressed_file": true} {
		_, err := Discover(Request{Source: Resolved{Source: Source{Gather: gather}}})
		assert.Equal(t, compiled, err == nil, gather)
	}
}
