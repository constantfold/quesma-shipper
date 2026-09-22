package sources

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHome = "/home/u"

// MatchTree licenses a walk to skip a directory, so only a "<root>/**" rule may answer yes.
func TestMatchTreeOnlyAnswersForWholeTrees(t *testing.T) {
	d := New(testHome)
	for dir, tree := range map[string]bool{
		"/.ssh": true, "/.ssh/keys": true, "/Library/Keychains": true,
		// Denied as a path by a basename or exact rule, but their contents are not.
		"/proj/.env": false, "/proj/release.key": false, "/.netrc": false, "/proj": false,
	} {
		denied, pat := d.MatchTree(testHome + dir)
		assert.Equalf(t, tree, denied, "%s (pattern %q)", dir, pat)
	}
}

func TestMatchPairChecksBothForms(t *testing.T) {
	home := realTempDir(t)
	secret := filepath.Join(home, ".ssh", "id_secret")
	plain := filepath.Join(home, "work", "notes.jsonl")
	writeFile(t, secret, "x")
	writeFile(t, plain, "x")
	// A benign name that resolves into the denied tree, and a denied location pointing at a harmless file.
	intoDenied := filepath.Join(home, "work", "notes-link.jsonl")
	outOfDenied := filepath.Join(home, ".ssh", "link.jsonl")
	if err := os.Symlink(secret, intoDenied); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	require.NoError(t, os.Symlink(plain, outOfDenied))
	d := New(home)

	for _, tc := range []struct {
		given, resolved string
		denied          bool
	}{
		{intoDenied, secret, true},
		// Without the resolved form only the literal path is checked, and it is clean.
		{intoDenied, "", false},
		{outOfDenied, plain, true},
		{plain, plain, false},
	} {
		denied, pat := d.MatchPair(tc.given, tc.resolved)
		assert.Equalf(t, tc.denied, denied, "MatchPair(%s, %s) = %q", tc.given, tc.resolved, pat)
	}
	_, pat := d.MatchPair(intoDenied, secret)
	assert.True(t, strings.HasSuffix(pat, "/.ssh/**"), pat)

	// Match resolves for itself and must reach the same verdicts.
	for p, denied := range map[string]bool{intoDenied: true, outOfDenied: true, secret: true, plain: false} {
		got, _ := d.Match(p)
		assert.Equal(t, denied, got, p)
	}
}

// Each row states the pattern the path must be reported against, or "" for one that stays collectable; "~" expands to testHome.
func TestMatchReportsTheFirstPatternInListOrder(t *testing.T) {
	type row struct{ path, want string }
	corpus := []row{
		// Denied roots, and the root itself.
		{"~/.ssh", "~/.ssh/**"},
		{"~/.ssh/config", "~/.ssh/**"},
		{"~/.ssh/nested/deeper/key", "~/.ssh/**"},
		{"~/.aws/credentials", "~/.aws/**"},
		{"~/.gnupg/pubring.kbx", "~/.gnupg/**"},
		{"~/.kube/config", "~/.kube/**"},
		{"~/.azure/msal_token_cache.json", "~/.azure/**"},
		{"~/.config/gh/hosts.yml", "~/.config/gh/**"},
		{"~/.config/gcloud", "~/.config/gcloud/**"},
		{"~/Library/Keychains/login.keychain-db", "~/Library/Keychains/**"},
		// Inside a denied tree AND matching an earlier pattern: the earlier one is reported, both directions.
		{"~/.ssh/id_rsa", "~/.ssh/**"},
		{"~/Library/Keychains/x.pem", "**/*.pem"},
		{"~/Library/Keychains/login.key", "**/*.key"},
		// Near misses on the roots.
		{"~/.sshfoo/config", ""},
		{"~/.ssh_backup", ""},
		{"~/.config/ghost/notes.jsonl", ""},
		// Exact files, and things next to them.
		{"~/.netrc", "~/.netrc"},
		{"~/.netrcx", ""},
		{"~/x/.netrc", ""},
		{"~/.npmrc", "~/.npmrc"},
		{"~/.pypirc", "~/.pypirc"},
		{"~/.git-credentials", "~/.git-credentials"},
		{"~/.claude.json", "~/.claude.json"},
		{"~/.claude.json.bak", ""},
		{"~/.claude/.credentials.json", "~/.claude/.credentials.json"},
		{"~/.claude/projects/p/a.jsonl", ""},
		{"~/.docker/config.json", "~/.docker/config.json"},
		{"~/.docker/daemon.json", ""},
		{"~/.codex/auth.json", "~/.codex/auth.json"},
		{"~/.config/opencode/auth.json", "~/.config/opencode/auth.json"},
		{"~/.local/share/opencode/auth.json", "~/.local/share/opencode/auth.json"},
		// Basenames, anywhere, and their near misses.
		{"~/proj/.env", "**/.env"},
		{"~/proj/.envy", ""},
		{"~/proj/.env.local", "**/.env.*"},
		{"~/proj/.env.", "**/.env.*"},
		{"~/proj/env", ""},
		{"~/proj/id_rsa", "**/id_rsa"},
		{"~/proj/id_rsa.pub", ""},
		{"~/proj/id_ed25519", "**/id_ed25519"},
		{"~/proj/deep/nest/.env", "**/.env"},
		{"/srv/shared/.env", "**/.env"},
		{"/.env", "**/.env"},
		// Extension rules.
		{"~/proj/server.pem", "**/*.pem"},
		{"~/proj/server.pem.old", ""},
		{"~/proj/.pem", "**/*.pem"},
		{"~/proj/bundle.p12", "**/*.p12"},
		{"~/proj/private.key", "**/*.key"},
		{"~/proj/keyfile", ""},
		// Ordinary files that must stay collectable.
		{"~/.claude/CLAUDE.md", ""},
		{"~/.codex/sessions/2026/r.jsonl", ""},
		{"~/work/project/src/db.go", ""},
		{"/var/log/app.log", ""},
		{"/", ""},
	}

	if runtime.GOOS == "windows" {
		corpus = append(corpus, row{"~/.SSH/id_rsa", "~/.ssh/**"}, row{"~/proj/.ENV", "**/.env"},
			row{"~/proj/ID_RSA", "**/id_rsa"}, row{"~/proj/PRIVATE.KEY", "**/*.key"})
	} else {
		corpus = append(corpus, row{"~/.SSH/id_rsa", "**/id_rsa"}, row{"~/proj/.ENV", ""},
			row{"~/proj/ID_RSA", ""}, row{"~/proj/PRIVATE.KEY", ""})
	}
	if os.Getenv("APPDATA") != "" {
		corpus = append(corpus, row{"$APPDATA/gcloud/credentials.db", "$APPDATA/gcloud/**"},
			row{"$APPDATA/GitHub CLI/hosts.yml", "$APPDATA/GitHub CLI/**"})
	}

	for _, home := range []string{testHome, t.TempDir()} {
		exp := func(s string) string {
			if s == "" {
				return ""
			}
			return normalize(os.ExpandEnv(strings.Replace(s, "~", home, 1)))
		}
		d := New(home)
		reported := map[string]bool{}
		for _, row := range corpus {
			path, want := exp(row.path), exp(row.want)
			reported[want] = true
			ok, pat := d.matchCandidate(path)
			assert.Truef(t, ok == (want != "") && pat == want, "%s: reported (%v, %q), want (%v, %q)", path, ok, pat, want != "", want)
			ok, pat = d.Match(path)
			assert.Equal(t, want != "", ok, path)
			assert.Equal(t, want, pat, path)
		}
		// A new compiled pattern needs a path that reports against it, or the corpus stops covering the list.
		for _, pat := range d.Patterns() {
			assert.Truef(t, reported[pat], "no corpus path is reported against %q: add one", pat)
		}
	}
}
