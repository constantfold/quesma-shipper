package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

func (r *Runtime) options(dryRun bool) engine.Options {
	return engine.Options{
		Plan:       planFor(r.eff),
		Identity:   r.unit,
		Upload:     r.upload,
		Log:        r.log,
		Enrichers:  Enrichers(),
		Env:        r.env,
		Recipients: r.recipients,
		DryRun:     dryRun,
		Client:     clientBlock(),
		Progress:   r.OnProgress,
		RunID:      r.runID,
	}
}

// Enrichers is shared with doctor so "in this build" cannot drift from what the engine runs.
func Enrichers() transforms.Registry {
	return transforms.NewRegistry(cursorjoin.New())
}

// Flush runs once under the store's flock, which every path shares, so runs cannot interleave.
func (r *Runtime) Flush(ctx context.Context, dryRun bool) (formats.Report, error) {
	return r.flushWith(ctx, dryRun, false)
}

// Drain flushes everything pending on an ephemeral host, bounded by the deadline rather than by
// max_files_per_run.
func (r *Runtime) Drain(ctx context.Context) (formats.Report, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.eff.DrainDeadline)
	defer cancel()

	rep, err := r.flushWith(ctx, false, true)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// Partial, not failed: files commit one at a time, so whatever got through is shipped.
		return rep, false, nil
	}
	if err != nil {
		return rep, false, err
	}
	return rep, !rep.Truncated, nil
}

func (r *Runtime) flushWith(ctx context.Context, dryRun, unbounded bool) (formats.Report, error) {
	store, err := engine.Open(r.eff.StateDir, r.unit.InstallID.String())
	if err != nil {
		return formats.Report{}, err
	}
	defer store.Close()
	if r.OnLocked != nil {
		r.OnLocked()
	}

	if !dryRun && r.uploadErr != nil {
		return formats.Report{}, r.uploadErr
	}

	o := r.options(dryRun)
	o.Unbounded = unbounded
	o.Heartbeat = r.WriteHeartbeat
	rep, err := engine.Run(ctx, store, o)

	// Stamped even when nothing shipped: the marker answers "is the agent running at all".
	if !dryRun {
		if markErr := packaging.RecordRun(r.eff.StateDir, time.Now()); markErr != nil && err == nil {
			fmt.Fprintf(os.Stderr, "warning: could not stamp the last-run marker: %v\n", markErr)
		}
	}
	return rep, err
}

// planFor hands the engine values, never the resolver, so a new config key does not touch it.
func planFor(eff *config.Effective) engine.Plan {
	interval, _ := config.TickInterval(eff.Schedule)
	return engine.Plan{
		Interval:       interval,
		OrganizationID: eff.OrganizationID,
		StateDir:       eff.StateDir,
		MaxFilesPerRun: eff.MaxFilesPerRun,
		Sources:        eff.Sources,
		RulePacks:      eff.RulePacks,
		SecretKeyNames: eff.SecretKeyNames,
		StructuralEx:   eff.StructuralEx,
		Deny:           eff.Deny,
		Ignore:         eff.Catalog.RepoFilter(),
		ConfigVersion:  eff.ConfigVersion,
		ConfigExpired:  eff.ConfigExpired,
	}
}
