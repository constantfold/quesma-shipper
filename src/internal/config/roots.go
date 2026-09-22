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

// resolveRoots checks each enabled source's roots against the compiled scope ceiling, then picks one.
func resolveRoots(eff *Effective, in Input) error {
	for i := range eff.Sources {
		src := &eff.Sources[i]
		if !src.Enabled {
			continue
		}
		spec, _ := in.Catalog.Source(src.ID)
		for _, candidate := range src.Roots {
			if !slices.Contains(spec.Roots, candidate) {
				return eff.reject("sources."+src.ID+".roots",
					"%q is outside the compiled scope ceiling %v: a new root requires a release", candidate, spec.Roots)
			}
		}
		root, reasons, err := pickRoot(eff, src, in.Env)
		if err != nil {
			return err
		}
		src.Root = root
		if root == "" {
			src.RootUnresolvedReason = strings.Join(reasons, "; ")
		}
	}
	return nil
}

// pickRoot returns the first usable candidate or why none was; an error is a config fault, an absent agent is "" and reasons.
func pickRoot(eff *Effective, src *ResolvedSource, env sources.Env) (string, []string, error) {
	rootsField := "sources." + src.ID + ".roots"
	var reasons []string
	for _, candidate := range src.Roots {
		expanded, err := env.ExpandRoot(candidate)
		var unset *sources.ErrUnsetVar
		switch {
		case errors.As(err, &unset):
			reasons = append(reasons, unset.Error())
			continue
		case err != nil:
			return "", reasons, eff.reject(rootsField, "%v", err)
		}
		// Deny is checked before existence: a root pointed into ~/.ssh is a refusal whether or not it exists.
		if err := eff.Deny.CheckRoot(expanded); err != nil {
			return "", reasons, eff.reject(rootsField, "%v", err)
		}
		// A missing root is the agent-absent case, kept distinguishable from a root that matches nothing.
		if info, err := os.Stat(expanded); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s does not exist", expanded))
			continue
		} else if !info.IsDir() {
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

// RefreshAbsentRoots retries only missing roots, so newly installed agents appear and resolved ones keep their fingerprint identity.
func RefreshAbsentRoots(eff *Effective, env sources.Env) []string {
	var found []string
	for i := range eff.Sources {
		src := &eff.Sources[i]
		if !src.Enabled || src.Root != "" {
			continue
		}
		root, reasons, err := pickRoot(eff, src, env)
		switch {
		case err != nil:
			src.RootUnresolvedReason = err.Error()
		case root == "":
			src.RootUnresolvedReason = strings.Join(reasons, "; ")
		default:
			src.Root, src.RootUnresolvedReason = root, ""
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
