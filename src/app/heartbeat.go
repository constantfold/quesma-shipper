package app

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// WriteHeartbeat publishes discovery health as an install-owned state object: under state/ but
// inside the install prefix, so one erasure sweep takes it too, and carrying no transcript bytes.
// `doctor` probes the write path with it, as it is the only state object the protocol authorizes.
func (r *Runtime) WriteHeartbeat(ctx context.Context, rep formats.Report) error {
	return r.writeHeartbeat(ctx, rep, true)
}

func (r *Runtime) writeHeartbeat(ctx context.Context, rep formats.Report, mirror bool) error {
	r.hbMu.Lock()
	defer r.hbMu.Unlock()
	hb := engine.Build(engine.Input{
		OrganizationID: r.eff.OrganizationID,
		InstallID:      r.unit.InstallID.String(),
		ClientVersion:  r.build.Version,
		ConfigVersion:  r.eff.ConfigVersion,
		ConfigExpired:  r.eff.ConfigExpired,
		RunID:          r.runID,
		Report:         rep,
		Now:            time.Now().UTC(),
		// The crash comes from this process reading the journal; the failures come from the
		// record, which may include this very run's judgement.
		FailureRecord: r.failureRecord(),
	})
	body, err := hb.Encode()
	if err != nil {
		return err
	}
	hash := transforms.Hash(body)

	// Mirrored in the clear (counts and versions, never payload bytes) so `quesma-shipper doctor` needs
	// no network call. Best-effort: a reporting nicety must never fail a flush.
	if mirror {
		_ = platform.WriteAtomic(filepath.Join(r.eff.StateDir, engine.Name), body, 0o600)
	}

	// The resolved organization, not a literal: the heartbeat has to land in the same subtree as
	// its mirror objects, or one erasure sweep would miss it.
	key, err := formats.StateKey(r.eff.OrganizationID, r.unit.InstallID.String(), engine.Name+".age")
	if err != nil {
		return err
	}
	sealed, _, err := transforms.Seal(transforms.Manifest{
		ManifestVersion: transforms.ManifestVersion,
		OrganizationID:  r.eff.OrganizationID,
		InstallID:       r.unit.InstallID.String(),
		SourceID:        "heartbeat",
		NativePath:      engine.Name,
		Gather:          "metadata_only",
		ArtifactClass:   "context",
		SourceHash:      hash,
		SealedAt:        time.Now().UTC().Format(time.RFC3339),
		ShapeSniff:      string(formats.SniffOK),
		// The same config fields every mirror manifest carries, so no reader special-cases this one.
		ConfigVersion: r.eff.ConfigVersion,
		ConfigExpired: r.eff.ConfigExpired,
		Client:        clientBlock(),
		RunID:         r.runID,
	}, body, r.recipients)
	if err != nil {
		return err
	}

	// The assembly failure first: a nil port and a recorded uploadErr are the same condition.
	if r.uploadErr != nil {
		return r.uploadErr
	}
	// The heartbeat goes down the trajectory path exactly: one authorization, the same validation,
	// the same PUT. No second way to reach the store, which a revocation would have to learn about.
	outcomes := r.upload.AuthorizeAndUpload(ctx, []engine.PreparedObject{{
		ObjectID:   "heartbeat",
		Key:        key,
		Body:       sealed,
		SourceHash: hash,
		Metadata:   map[string]string{"kind": "heartbeat"},
	}})
	if len(outcomes) != 1 {
		return fmt.Errorf("the upload port answered %d outcomes for one heartbeat", len(outcomes))
	}
	// Once: the stall watchdog's heartbeat can carry the crash before the engine's own does.
	if outcomes[0] == nil && r.lastCrash != nil && r.OnCrashShipped != nil {
		r.crashOnce.Do(r.OnCrashShipped)
	}
	return outcomes[0]
}

// clientBlock is the build identity stamped into every object. One place, because it is a wire
// contract the ETL groups on: a second construction site is how two objects disagree.
func clientBlock() transforms.Client {
	b := platform.Current()
	return transforms.Client{
		Version:   b.String(),
		Commit:    b.Revision,
		Modified:  b.Modified,
		GoVersion: b.GoVersion,
		OS:        b.OS,
		Arch:      b.Arch,
	}
}
