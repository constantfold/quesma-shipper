package sources

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// unreadable is what a walk could not look at, counted rather than collapsed into a single error.
type unreadable struct {
	count   int
	example string
	err     error
}

func (u unreadable) reason() string {
	if u.count == 0 {
		return ""
	}
	if u.count == 1 {
		return fmt.Sprintf("%s: %v", u.example, u.err)
	}
	return fmt.Sprintf("%d paths unreadable, first %s: %v", u.count, u.example, u.err)
}

// walkGlobs walks the root once against the globs, the deny list and the ignore list (the last return says
// whether ignore dropped anything); symlinks below the root are never followed, pairing with O_NOFOLLOW at open.
func walkGlobs(src Resolved, deny *List, ignore *RepoFilter) ([]Candidate, []Oversize, unreadable, bool) {
	var out []Candidate
	var oversize []Oversize
	var bad unreadable
	include, exclude := normalizeGlobs(src.Include), normalizeGlobs(src.Exclude)
	ignored := false
	if deny == nil {
		deny = &List{}
	}

	// A candidate is never a symlink, so resolving its parent once answers for every file in it; "" means
	// the parent resolves to itself or not at all.
	resolvedDirs := map[string]string{}
	resolveName := func(p string) string {
		dir := filepath.Dir(p)
		r, ok := resolvedDirs[dir]
		if !ok {
			r, _ = filepath.EvalSymlinks(dir)
			resolvedDirs[dir] = r
		}
		if r == "" || r == dir {
			return ""
		}
		return filepath.Join(r, filepath.Base(p))
	}

	note := func(path string, err error) {
		bad.count++
		if bad.err == nil {
			bad.example, bad.err = path, err
		}
	}

	// The ROOT may be a symlink, and only the root: ~/.claude -> ~/dotfiles/claude is what stow and chezmoi
	// produce, and WalkDir would lstat it and descend into nothing. Entries inside are still not followed, and
	// the resolved root is re-checked against the deny list.
	root := src.Root
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil && resolved != root {
		if denied, pattern := deny.Match(resolved); denied {
			note(root, fmt.Errorf("root resolves to %s, which the deny list refuses (%s)", resolved, pattern))
			return out, oversize, bad, ignored
		}
		root = resolved
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A permission denial deep in a store must not abort the walk; what could not be read is counted.
			note(path, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// MatchTree, not Match: only a whole-tree pattern licenses pruning, and the per-file check below stays the authority.
			if denied, _ := deny.MatchTree(path); denied {
				return fs.SkipDir
			}
			return nil
		}
		// Type() reports the entry's own type, so a symlink is skipped rather than followed.
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)

		if !matchesAny(rel, include) || matchesAny(rel, exclude) {
			return nil
		}
		// The path as the operator spells it: what downstream records, and what the deny list is written against.
		named := filepath.Join(src.Root, rel)

		// BOTH spellings: the walk may run under a resolved root (~/.claude -> ~/dotfiles/claude, /var -> /private/var),
		// so a rule written against one does not match a string built from the other. A file is denied if EITHER name is.
		if denied, _ := deny.MatchPair(path, resolveName(path)); denied {
			return nil
		}
		if named != path {
			if denied, _ := deny.MatchPair(named, resolveName(named)); denied {
				return nil
			}
		}

		// Before the size cap, so an ignored repository's oversized file is not reported by name either.
		if ignore.Match(src, Candidate{Path: named, RelPath: rel}) {
			ignored = true
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			note(path, infoErr)
			return nil
		}
		if src.MaxFileBytes > 0 && info.Size() > src.MaxFileBytes {
			// Over the budget: counted on its own channel, since a policy decision is not a path that could not be read.
			oversize = append(oversize, Oversize{
				RelPath: rel, Size: info.Size(), Limit: src.MaxFileBytes,
			})
			return nil
		}

		// Reported under the CONFIGURED root, not the resolved one: native_path, the audit log and the state key must
		// keep the operator's spelling, or resolving a symlink orphans every fingerprint in the archive.
		out = append(out, Candidate{
			Load:    fileLoader(named, src.MaxFileBytes),
			Path:    named,
			RelPath: rel,
			Size:    info.Size(),
			MTime:   info.ModTime().UTC(),
		})
		return nil
	})
	// A walk that failed at the root: WalkDir's own error, which the callback never saw.
	if err != nil && bad.err == nil {
		note(src.Root, err)
	}
	return out, oversize, bad, ignored
}

// matchesAny expects patterns already normalised by normalizeGlobs.
func matchesAny(rel string, patterns []string) bool {
	for _, p := range patterns {
		if ok, err := doublestar.Match(p, rel); err == nil && ok {
			return true
		}
	}
	return false
}

func normalizeGlobs(globs []string) []string {
	out := make([]string, len(globs))
	for i, g := range globs {
		out[i] = strings.TrimPrefix(filepath.ToSlash(g), "/")
	}
	return out
}
