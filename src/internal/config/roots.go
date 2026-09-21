package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// resolveRoots expands each source's root candidates, then applies the deny list to the symlink-resolved path and require_subdir.
func resolveRoots(eff *Effective, in Input) error {
	compiled := in.Catalog

	for i := range eff.Sources {
		src := &eff.Sources[i]
		if !src.Enabled {
			continue
		}

		spec, _ := compiled.Source(src.ID)
		rootsField := "sources." + src.ID + ".roots"

		// The scope ceiling: a root must be one the compiled catalog declared for this source.
		for _, candidate := range src.Roots {
			if !slices.Contains(spec.Roots, candidate) {
				return eff.reject(rootsField, "%q is outside the compiled scope ceiling %v: a new root requires a release", candidate, spec.Roots)
			}
		}

		root, reasons, rej := pickRoot(eff, src, in.Env)
		if rej != nil {
			return rej
		}
		src.Root = root
		if src.Root == "" {
			src.RootUnresolvedReason = strings.Join(reasons, "; ")
		}
	}
	return nil
}

// pickRoot returns the first candidate that expands, exists and satisfies require_subdir, or the
// reasons no candidate qualified. A RejectionError separates a configuration fault -- a candidate
// that cannot expand, or one the deny list forbids -- from the ordinary absent agent, which is an
// empty root and a reason.
func pickRoot(eff *Effective, src *ResolvedSource, env sources.Env) (string, []string, error) {
	rootsField := "sources." + src.ID + ".roots"
	var reasons []string
	for _, candidate := range src.Roots {
		expanded, err := env.ExpandRoot(candidate)
		if err != nil {
			var unset *sources.ErrUnsetVar
			if errors.As(err, &unset) {
				reasons = append(reasons, unset.Error())
				continue
			}
			return "", reasons, eff.reject(rootsField, "%v", err)
		}

		// Deny is checked before existence: a root pointed into ~/.ssh is a refusal whether or not it exists.
		if err := eff.Deny.CheckRoot(expanded); err != nil {
			return "", reasons, eff.reject(rootsField, "%v", err)
		}

		// A missing root is the agent-absent case: expected silence, kept distinguishable from a root that matches nothing.
		info, statErr := os.Stat(expanded)
		if statErr != nil {
			reasons = append(reasons, fmt.Sprintf("%s does not exist", expanded))
			continue
		}
		if !info.IsDir() {
			reasons = append(reasons, fmt.Sprintf("%s is not a directory", expanded))
			continue
		}

		if err := requireSubdir(expanded, src.RequireSubdir); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if err := eff.Deny.CheckIncludes(expanded, src.Include); err != nil {
			return "", reasons, eff.reject("sources."+src.ID+".include", "%v", err)
		}

		return expanded, reasons, nil
	}
	return "", reasons, nil
}

// RefreshAbsentRoots retries missing roots so newly installed agents become visible.
// Resolved roots stay fixed to preserve fingerprint identity; failures leave a source absent.
func RefreshAbsentRoots(eff *Effective, env sources.Env) []string {
	var found []string
	for i := range eff.Sources {
		src := &eff.Sources[i]
		if !src.Enabled || src.Root != "" {
			continue
		}
		root, reasons, rej := pickRoot(eff, src, env)
		switch {
		case rej != nil:
			src.RootUnresolvedReason = rej.Error()
		case root == "":
			src.RootUnresolvedReason = strings.Join(reasons, "; ")
		default:
			src.Root = root
			src.RootUnresolvedReason = ""
			found = append(found, src.ID)
		}
	}
	return found
}

// requireSubdir refuses a root without the declared subdirectory: a claimed store that does not look like one is not one.
func requireSubdir(root, subdir string) error {
	if subdir == "" {
		return nil
	}
	info, err := os.Stat(filepath.Join(root, subdir))
	if err != nil {
		return fmt.Errorf("root %s has no %s/ directory", root, subdir)
	}
	if !info.IsDir() {
		return fmt.Errorf("root %s: %s exists but is not a directory", root, subdir)
	}
	return nil
}
