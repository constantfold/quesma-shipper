package sources

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// gitRemoteFor walks up to the nearest .git and reads a url out of its config; insteadOf rules and credential helpers are ignored.
func gitRemoteFor(cwd string, cfg *GitRead) (remote, project, gaveUp string) {
	if cfg == nil {
		return "", "", "no git_read configured"
	}

	_, gitDir, ok := findGitDir(cwd, cfg, "")
	if !ok {
		// The trajectory outlives the checkout: a cwd that no longer exists is expected, not a failure.
		return "", "", "no .git found above " + filepath.Base(cwd)
	}

	raw, _, err := platform.ReadWhole(filepath.Join(gitDir, "config"), 1<<20)
	if err != nil {
		return "", "", "git config unreadable"
	}

	for _, u := range remoteURLs(string(raw), cfg.Take) {
		if normalised, name, err := NormaliseRemote(u); err == nil {
			return normalised, name, ""
		}
	}
	return "", "", "no usable remote in git config"
}

// findGitDir returns the checkout root and the COMMON git dir: a linked worktree's own gitdir holds no config.
func findGitDir(cwd string, cfg *GitRead, ceiling string) (root, common string, ok bool) {
	if !filepath.IsAbs(cwd) {
		return "", "", false
	}
	dir := filepath.Clean(cwd)
	for dir != ceiling {
		candidate := filepath.Join(dir, ".git")
		info, err := os.Lstat(candidate)
		if err == nil {
			if info.IsDir() {
				return dir, candidate, true
			}
			// A worktree: .git is a file holding "gitdir: <path>".
			if cfg.FollowGitdirFile {
				if target, ok := gitPointer(candidate, "gitdir:", dir); ok {
					return dir, gitCommonDir(target), true
				}
			}
			return "", "", false
		}
		if !cfg.WalkUp {
			return "", "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false
		}
		dir = parent
	}
	return "", "", false
}

// gitPointer reads a "gitdir:" line or commondir's bare path and resolves it against base.
func gitPointer(file, prefix, base string) (string, bool) {
	body, _, err := platform.ReadWhole(file, 64<<10)
	if err != nil {
		return "", false
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(body)), prefix)
	target = filepath.FromSlash(strings.TrimSpace(target))
	if !ok || target == "" {
		return "", false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(base, target)
	}
	return filepath.Clean(target), true
}

// gitCommonDir follows a linked worktree's commondir; none means this is the common dir.
func gitCommonDir(gitDir string) string {
	if common, ok := gitPointer(filepath.Join(gitDir, "commondir"), "", gitDir); ok {
		return common
	}
	return gitDir
}

// mainWorktreeDir is the checkout holding the common git dir; "" for a bare repository.
func mainWorktreeDir(commonDir string) string {
	if filepath.Base(commonDir) == ".git" {
		return filepath.Dir(commonDir)
	}
	return ""
}

func remoteURLs(body string, take []string) []string {
	if len(take) > 0 && !slices.ContainsFunc(take, func(t string) bool { return strings.Contains(t, "url") }) {
		return nil
	}

	var out []string
	for line := range strings.SplitSeq(body, "\n") {
		if key, value, found := strings.Cut(line, "="); found && strings.TrimSpace(key) == "url" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

// NormaliseRemote returns one host/path label for ssh and https alike, ALWAYS dropping userinfo, which can be a live credential.
func NormaliseRemote(raw string) (hostPath, project string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", fmt.Errorf("empty remote")
	}

	// scp-like syntax: git@github.com:org/repo.git
	if !strings.Contains(trimmed, "://") {
		if before, after, found := strings.Cut(trimmed, ":"); found && !strings.HasPrefix(trimmed, "/") {
			host := before
			if _, h, ok := strings.Cut(before, "@"); ok {
				host = h
			}
			return finishRemote(host, after)
		}
		// A bare path is a local remote.
		return "", "", fmt.Errorf("local filesystem remote")
	}

	u, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", "", parseErr
	}
	switch u.Scheme {
	case "file", "":
		return "", "", fmt.Errorf("local filesystem remote")
	}
	// u.Hostname() drops userinfo AND the port, so no credential survives and one repository keeps one label.
	return finishRemote(u.Hostname(), u.Path)
}

func finishRemote(host, path string) (string, string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", "", fmt.Errorf("remote has no host")
	}
	path = strings.Trim(strings.TrimSuffix(strings.TrimSpace(path), ".git"), "/")
	if path == "" {
		return "", "", fmt.Errorf("remote has no path")
	}
	project := path[strings.LastIndex(path, "/")+1:]
	return host + "/" + path, project, nil
}
