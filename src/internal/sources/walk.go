package sources

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
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

// walkGlobs never follows symlinks below the root, pairing with O_NOFOLLOW at open; the bool says ignore dropped something.
func walkGlobs(src Resolved, deny *List, ignore *RepoFilter) ([]Candidate, []Oversize, unreadable, bool) {
	var out []Candidate
	var oversize []Oversize
	var bad unreadable
	include, exclude := normalizeGlobs(src.Include), normalizeGlobs(src.Exclude)
	ignored := false
	if deny == nil {
		deny = &List{}
	}

	// Candidates are never symlinks, so one parent resolution serves every file in it; "" means nothing to add.
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

	// Only the root may be a symlink (stow and chezmoi make ~/.claude one); its target is re-checked against the deny list.
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

		// Under a resolved root a rule may match only one spelling, so a file is denied if EITHER name is.
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
			oversize = append(oversize, Oversize{RelPath: rel, Size: info.Size(), Limit: src.MaxFileBytes})
			return nil
		}

		// Reported under the CONFIGURED root: resolving a symlink here would orphan every fingerprint in the archive.
		out = append(out, Candidate{Path: named, RelPath: rel, Size: info.Size(), MTime: info.ModTime().UTC(),
			Load: fileLoader(named, src.MaxFileBytes)})
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
	return slices.ContainsFunc(patterns, func(p string) bool {
		ok, err := doublestar.Match(p, rel)
		return err == nil && ok
	})
}

func normalizeGlobs(globs []string) []string {
	out := make([]string, len(globs))
	for i, g := range globs {
		out[i] = strings.TrimPrefix(filepath.ToSlash(g), "/")
	}
	return out
}
