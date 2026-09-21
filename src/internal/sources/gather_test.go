package sources_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func source(root string, include []string) config.ResolvedSource {
	return config.ResolvedSource{
		Source: sources.Source{
			ID:      "claude-code-transcripts",
			Family:  "claude-code",
			Gather:  "file_glob",
			Include: include,
			Sniff:   &sources.Sniff{Kind: "jsonl", MaxScanBytes: 65536},
		},
		Root:    root,
		Enabled: true,
	}
}

func discover(t *testing.T, src config.ResolvedSource, deny *sources.List) sources.Discovery {
	t.Helper()
	d, err := sources.Discover(sources.Request{Source: src, Deny: deny, StateDir: t.TempDir()})
	require.NoError(t, err)
	return d
}

func TestDiscoversMatchingFiles(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "projects", "p", "a.jsonl"), `{"type":"user","version":"2.1.220"}`+"\n")
	write(t, filepath.Join(root, "projects", "p", "b.jsonl"), `{"type":"user"}`+"\n")
	write(t, filepath.Join(root, "projects", "p", "notes.md"), "# not matched\n")

	d := discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)

	assert.Equalf(t, sources.Collected, d.Health, "health %q, reason %q", d.Health, d.Reason)
	require.Lenf(t, d.Candidates, 2, "expected 2 candidates, got %d", len(d.Candidates))
	for _, c := range d.Candidates {
		assert.True(t, !strings.HasSuffix(c.RelPath, ".md"), "a non-matching file was collected")
		assert.Truef(t, filepath.IsAbs(c.Path), "candidate path should be absolute: %q", c.Path)
	}
}

// agent_absent is expected silence, root_present_no_match is probable drift; confusing them makes a moved store look like an idle user.
func TestAgentAbsentIsDistinguishableFromNoMatch(t *testing.T) {
	// No root at all.
	absent := source("", []string{"projects/**/*.jsonl"})
	absent.RootUnresolvedReason = "~/.claude does not exist"
	d := discover(t, absent, nil)
	assert.Equalf(t, sources.AgentAbsent, d.Health, "an unresolved root must be agent_absent, got %q", d.Health)
	assert.NotEqual(t, "", d.Reason, "agent_absent must carry a reason for doctor")

	// Root present, glob matches nothing.
	root := t.TempDir()
	write(t, filepath.Join(root, "projects", "p", "notes.md"), "# nothing to collect\n")
	d = discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)
	assert.Equalf(t, sources.RootPresentNoMatch, d.Health, "a present root with no match must be root_present_no_match, got %q", d.Health)
	assert.Len(t, d.Candidates, 0, "no candidates should be reported")
}

// Health is emitted even at zero bytes: a pass that returns nothing and says nothing is the silent-zero failure.
func TestHealthIsEmittedAtZeroCandidates(t *testing.T) {
	for _, src := range []config.ResolvedSource{
		source("", []string{"**/*.jsonl"}),
		source(t.TempDir(), []string{"**/*.jsonl"}),
	} {
		d := discover(t, src, nil)
		assert.NotEqual(t, sources.HealthState(""), d.Health, "health must never be empty")
		assert.Truef(t, d.Health == sources.Collected || d.Reason != "", "health %q must carry a reason", d.Health)
	}
}

// Retention-aware ordering: a bounded run must take the files closest to deletion first.
func TestCandidatesAreOldestFirst(t *testing.T) {
	root := t.TempDir()
	older := filepath.Join(root, "projects", "p", "older.jsonl")
	newer := filepath.Join(root, "projects", "p", "newer.jsonl")
	write(t, older, `{"a":1}`+"\n")
	write(t, newer, `{"a":2}`+"\n")

	old := mustParse(t, "2026-01-01T00:00:00Z")
	recent := mustParse(t, "2026-07-30T00:00:00Z")
	require.NoError(t, os.Chtimes(older, old, old))
	require.NoError(t, os.Chtimes(newer, recent, recent))

	d := discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)
	require.Lenf(t, d.Candidates, 2, "expected 2 candidates, got %d", len(d.Candidates))
	if !strings.HasSuffix(d.Candidates[0].RelPath, "older.jsonl") {
		t.Errorf("oldest must come first, got %v", []string{d.Candidates[0].RelPath, d.Candidates[1].RelPath})
	}
}

// Shape drift blocks collection; empty sessions and both agents' version headers remain collectable.
func TestDiscoverySniffsStoreShapeAndVersion(t *testing.T) {
	for _, tc := range []struct {
		name, path, glob, body, version string
		sniff                           sources.SniffResult
	}{
		{"HighEntropyStoreDegradesToUnreadable", "projects/p/a.jsonl", "projects/**/*.jsonl",
			"\x00\x01\x02binary garbage\x00", "", sources.SniffUnexpectedShape},
		{"SQLiteReplacingJSONLIsCaughtByTheSniff", "projects/p/a.jsonl", "projects/**/*.jsonl",
			"SQLite format 3\x00\x04\x00\x01", "", sources.SniffUnexpectedShape},
		{"EmptyFileSniffsAsEmptyNotBroken", "projects/p/a.jsonl", "projects/**/*.jsonl", "", "", sources.SniffEmpty},
		{"AgentVersionIsObservedFromTheStore", "projects/p/a.jsonl", "projects/**/*.jsonl",
			`{"type":"user","uuid":"u1","version":"2.1.220"}` + "\n", "2.1.220", sources.SniffOK},
		{"AgentVersionIsFoundBelowTheFirstLine", "projects/p/a.jsonl", "projects/**/*.jsonl",
			`{"type":"summary","sessionId":"s"}` + "\n" +
				`{"type":"user","sessionId":"s"}` + "\n" +
				`{"type":"assistant","version":"2.1.245"}` + "\n", "2.1.245", sources.SniffOK},
		{"CodexNestedVersionIsObserved", "sessions/r.jsonl", "sessions/**/*.jsonl",
			`{"timestamp":"t","type":"session_meta","payload":{"cli_version":"0.144.1"}}` + "\n", "0.144.1", sources.SniffOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, filepath.Join(root, tc.path), tc.body)
			d := discover(t, source(root, []string{tc.glob}), nil)
			assert.Equal(t, tc.sniff, d.Sniff)
			assert.Equal(t, tc.version, d.AgentVersion)
			if tc.sniff == sources.SniffUnexpectedShape {
				assert.Equal(t, sources.MatchPresentUnreadable, d.Health)
				assert.Empty(t, d.Candidates)
			} else {
				assert.Equal(t, sources.Collected, d.Health)
				assert.Len(t, d.Candidates, 1)
			}
		})
	}
}

// The reported version is the newest readable session's.
func TestAgentVersionComesFromTheNewestFile(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "projects", "p", "old.jsonl")
	write(t, old, `{"type":"user","version":"2.1.100"}`+"\n")
	older(t, old)
	write(t, filepath.Join(root, "projects", "p", "new.jsonl"),
		`{"type":"user","version":"2.1.245"}`+"\n")

	d := discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)
	assert.Equalf(t, "2.1.245", d.AgentVersion, "agent version %q, want the newest file's 2.1.245", d.AgentVersion)
}

// The walk does not follow symlinks, which pairs with O_NOFOLLOW at open time; neither is sufficient alone.
func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.jsonl"), `{"secret":true}`+"\n")
	write(t, filepath.Join(root, "projects", "p", "real.jsonl"), `{"a":1}`+"\n")

	link := filepath.Join(root, "projects", "p", "linked.jsonl")
	if err := os.Symlink(filepath.Join(outside, "secret.jsonl"), link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	d := discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)
	for _, c := range d.Candidates {
		assert.NotContains(t, c.RelPath, "linked", "a symlinked file was discovered")
	}
	assert.Lenf(t, d.Candidates, 1, "expected only the real file, got %d candidates", len(d.Candidates))
}

// The deny list is the read-time authority: a credential file can appear after config validation has passed.
func TestDenyListAppliesAtDiscoveryTime(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".claude")
	write(t, filepath.Join(root, "projects", "p", "a.jsonl"), `{"a":1}`+"\n")
	write(t, filepath.Join(root, ".credentials.json"), `{"accessToken":"secret"}`)

	deny := sources.New(home)
	// A glob wide enough to reach the credential file, as a hostile config would.
	d := discover(t, source(root, []string{"**"}), deny)

	for _, c := range d.Candidates {
		require.NotContainsf(t, c.RelPath, "credentials", "a denied file was offered for shipping: %s", c.RelPath)
	}
	assert.NotEqual(t, 0, len(d.Candidates), "the legitimate file should still be collected")
}

// A candidate's own name is always literal, but its parent may link into a denied tree: dropping that resolution ships this file.
func TestASymlinkedParentIntoADeniedTreeIsStillDenied(t *testing.T) {
	home := realTempDir(t)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	write(t, filepath.Join(home, ".ssh", "store", "leak.jsonl"), `{"token":"x"}`+"\n")
	// The root is reached through "link", which is really ~/.ssh.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	root := filepath.Join(home, "link", "store")
	d := discover(t, source(root, []string{"**"}), sources.New(home))

	assert.Lenf(t, d.Candidates, 0, "a file inside the ssh store was offered for shipping: %v", d.Candidates)
}

// A denied tree is pruned, not walked and rejected file by file; the file below is denied by nothing on its own name.
func TestADeniedTreeIsNotWalked(t *testing.T) {
	home := realTempDir(t)
	write(t, filepath.Join(home, "work", "a.jsonl"), `{"a":1}`+"\n")
	secret := filepath.Join(home, ".ssh")
	write(t, filepath.Join(secret, "store", "leak.jsonl"), `{"token":"x"}`+"\n")
	if os.Geteuid() != 0 {
		// Unreadable, so descending into it would also be counted and reported.
		require.NoError(t, os.Chmod(secret, 0o000))
		t.Cleanup(func() { _ = os.Chmod(secret, 0o700) })
	}

	d := discover(t, source(home, []string{"**"}), sources.New(home))

	for _, c := range d.Candidates {
		assert.NotContainsf(t, c.RelPath, ".ssh", "a file under a denied tree was collected: %s", c.RelPath)
	}
	assert.Equalf(t, 0, d.Unreadable, "the denied tree was opened: %s", d.UnreadableReason)
	assert.Lenf(t, d.Candidates, 1, "expected the one legitimate file, got %d", len(d.Candidates))
}

// Pruning may only follow a whole-tree rule: a directory named .env holds ordinary transcripts.
func TestADirectoryNamedLikeADeniedFileIsStillWalked(t *testing.T) {
	home := realTempDir(t)
	root := filepath.Join(home, ".claude")
	write(t, filepath.Join(root, "projects", ".env", "a.jsonl"), `{"a":1}`+"\n")
	write(t, filepath.Join(root, "projects", "release.key", "b.jsonl"), `{"b":2}`+"\n")
	write(t, filepath.Join(root, "projects", ".env", ".env"), "TOKEN=x\n")

	d := discover(t, source(root, []string{"**"}), sources.New(home))

	var got []string
	for _, c := range d.Candidates {
		got = append(got, c.RelPath)
	}
	for _, want := range []string{"projects/.env/a.jsonl", "projects/release.key/b.jsonl"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		assert.Truef(t, found, "collected %v, missing %s", got, want)
	}
	// The credential file itself is still denied by its own name.
	assert.Lenf(t, got, 2, "collected %v, expected the two transcripts and nothing else", got)
}

// A temporary directory with its own symlinks resolved, so the test is not measuring /var -> /private/var.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

func TestExcludeGlobsAreHonoured(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "projects", "p", "keep.jsonl"), `{"a":1}`+"\n")
	write(t, filepath.Join(root, "projects", "node_modules", "skip.jsonl"), `{"a":2}`+"\n")

	src := source(root, []string{"projects/**/*.jsonl"})
	src.Exclude = []string{"**/node_modules/**"}

	d := discover(t, src, nil)
	assert.Truef(t, len(d.Candidates) == 1 && strings.HasSuffix(d.Candidates[0].RelPath, "keep.jsonl"), "exclude not honoured: %v", d.Candidates)
}

// A permission denial deep in a store must not abort the walk: everything readable still ships, and the problem is reported.
func TestUnreadableSubtreeDoesNotAbortTheWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not apply")
	}
	root := t.TempDir()
	write(t, filepath.Join(root, "projects", "open", "a.jsonl"), `{"a":1}`+"\n")
	closed := filepath.Join(root, "projects", "closed")
	write(t, filepath.Join(closed, "b.jsonl"), `{"a":2}`+"\n")
	require.NoError(t, os.Chmod(closed, 0o000))
	t.Cleanup(func() { os.Chmod(closed, 0o700) })

	d := discover(t, source(root, []string{"projects/**/*.jsonl"}), nil)
	assert.Lenf(t, d.Candidates, 1, "the readable file should still be collected, got %d candidates", len(d.Candidates))
}

func TestRegistryHasNoReservedPrimitives(t *testing.T) {
	for _, reserved := range []string{"acp", "cloud_pull", "sqlite_rows"} {
		if _, err := sources.Discover(sources.Request{Source: sources.Resolved{Source: sources.Source{Gather: reserved}}}); err == nil {
			t.Errorf("%q must not be a compiled primitive", reserved)
		}
	}
	for _, expected := range []string{"file_glob", "compressed_file"} {
		if _, err := sources.Discover(sources.Request{Source: sources.Resolved{Source: sources.Source{Gather: expected}}}); err != nil {
			t.Errorf("%q should be compiled in: %v", expected, err)
		}
	}
}

func TestCompressedFileMagicSniff(t *testing.T) {
	root := t.TempDir()
	// zstd magic, then arbitrary bytes.
	write(t, filepath.Join(root, "sessions", "r.jsonl.zst"), "\x28\xb5\x2f\xfd\x00\x01\x02")

	src := source(root, []string{"sessions/**/*.jsonl.zst"})
	src.Gather = "compressed_file"
	src.Sniff = &sources.Sniff{Kind: "magic", MagicHex: "28b52ffd"}

	d := discover(t, src, nil)
	assert.Equalf(t, sources.SniffOK, d.Sniff, "valid zstd magic should sniff ok, got %q", d.Sniff)

	// Wrong magic: the file is not what the catalog says it is.
	write(t, filepath.Join(root, "sessions", "r.jsonl.zst"), "not zstd at all")
	d = discover(t, src, nil)
	assert.Equalf(t, sources.SniffUnexpectedShape, d.Sniff, "wrong magic should be unexpected_shape, got %q", d.Sniff)
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	p, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return p
}
