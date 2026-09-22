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

// ResolveEffective resolves every local layer plus whatever remote layer is already on disk. No
// network call: a read-only verb must explain the config in force without a round-trip.
func ResolveEffective() (*config.Effective, config.Paths, error) {
	eff, paths, _, err := resolve(context.Background(), true)
	return eff, paths, err
}

// ResolveOnline refreshes the remote layer first, then resolves. A refresh that fails falls back
// to the cached config and reports why; collection continues either way.
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

	// Known before the remote fetch, since the enrollment and config cache live there; only local
	// layers may set state_dir.
	paths.StateDir = stateDirFrom(layers, paths.StateDir)

	// A missing record means standalone; an unusable one is refused, or an enrolled install would
	// silently downgrade to "no backend".
	enrollment, err := controlplane.LoadEnrollment(paths.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, paths, controlplane.Remote{}, fmt.Errorf(
			"%w\n\nThis install is enrolled but its enrollment record cannot be used. "+
				"Fix the file or log in again with `quesma-shipper login`; collecting without it would ship "+
				"under different credentials than the ones this install was granted", err)
	}
	remote := controlplane.Refresh(ctx, controlplane.RefreshOptions{
		Enrollment: enrollment,
		StateDir:   paths.StateDir,
		Now:        time.Now(),
		Offline:    offline,
	})

	if remote.Doc != nil {
		layers = append(layers, config.LayeredDocument{Layer: config.LayerRemote, Doc: remote.Doc})
	}

	eff, err := config.Resolve(config.Input{
		Catalog:       compiled,
		Layers:        layers,
		ConfigExpired: remote.Expired,
		Env:           env,
		StateDir:      paths.StateDir,
	})
	if err != nil {
		return nil, paths, remote, err
	}
	// The identity unit and the fingerprint document persist together in the directory in force.
	paths.StateDir = eff.StateDir
	return eff, paths, remote, nil
}

// stateDirFrom lets the last layer that sets state_dir win, as Resolve does.
func stateDirFrom(layers []config.LayeredDocument, def string) string {
	out := def
	for _, ld := range layers {
		if ld.Doc != nil && ld.Doc.StateDir != nil && *ld.Doc.StateDir != "" {
			out = *ld.Doc.StateDir
		}
	}
	return out
}
