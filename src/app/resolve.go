package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// ResolveEffective uses only what is on disk, so a read-only verb never makes a network call.
func ResolveEffective() (*config.Effective, config.Paths, error) {
	eff, paths, _, err := resolve(context.Background(), true)
	return eff, paths, err
}

// ResolveOnline refreshes the remote layer first, falling back to the cached config if that fails.
func ResolveOnline(ctx context.Context) (*config.Effective, config.Paths, controlplane.Remote, error) {
	return resolve(ctx, false)
}

func resolve(ctx context.Context, offline bool) (*config.Effective, config.Paths, controlplane.Remote, error) {
	env, err := sources.OSEnv()
	if err != nil {
		return nil, config.Paths{}, controlplane.Remote{}, err
	}
	paths := config.DefaultPaths(env.Home, env.Lookup)

	layers, err := config.LoadLayers(paths)
	if err != nil {
		return nil, paths, controlplane.Remote{}, err
	}
	compiled, err := sources.Load()
	if err != nil {
		return nil, paths, controlplane.Remote{}, err
	}

	// Only local layers may set state_dir, which must be known before the remote fetch; the last one wins, as in Resolve.
	for _, ld := range layers {
		if ld.Doc != nil && ld.Doc.StateDir != nil && *ld.Doc.StateDir != "" {
			paths.StateDir = *ld.Doc.StateDir
		}
	}

	// An unusable record is refused, or an enrolled install would silently downgrade to standalone.
	enrollment, err := controlplane.LoadEnrollment(paths.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, paths, controlplane.Remote{}, fmt.Errorf(
			"%w\n\nThis install is enrolled but its enrollment record cannot be used. "+
				"Fix the file or log in again with `quesma-shipper login`; collecting without it would ship "+
				"under different credentials than the ones this install was granted", err)
	}
	remote := controlplane.Refresh(ctx, controlplane.RefreshOptions{Enrollment: enrollment, StateDir: paths.StateDir,
		Now: time.Now(), Offline: offline})

	if remote.Doc != nil {
		layers = append(layers, config.LayeredDocument{Layer: config.LayerRemote, Doc: remote.Doc})
	}

	eff, err := config.Resolve(config.Input{Catalog: compiled, Layers: layers, ConfigExpired: remote.Expired,
		Env: env, StateDir: paths.StateDir})
	if err != nil {
		return nil, paths, remote, err
	}
	// The identity unit and the fingerprint document persist together in the directory in force.
	paths.StateDir = eff.StateDir
	return eff, paths, remote, nil
}
