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

// WriteHeartbeat publishes discovery health as a state object inside the install prefix, so one
// erasure sweep takes it too. It carries no transcript bytes.
func (r *Runtime) WriteHeartbeat(ctx context.Context, rep formats.Report) error {
	return r.writeHeartbeat(ctx, rep, true)
}

func (r *Runtime) writeHeartbeat(ctx context.Context, rep formats.Report, mirror bool) error {
	r.hbMu.Lock()
	defer r.hbMu.Unlock()
	now := time.Now()
	hb := (engine.Heartbeat{
		OrganizationID: r.eff.OrganizationID,
		InstallID:      r.unit.InstallID.String(),
		ClientVersion:  r.build.Version,
		ConfigVersion:  r.eff.ConfigVersion,
		ConfigExpired:  r.eff.ConfigExpired,
		RunID:          r.runID,
		FailureRecord:  r.failureRecord(),
	}).WithReport(rep, now)
	body, err := hb.Encode()
	if err != nil {
		return err
	}
	hash := transforms.Hash(body)

	// Mirrored in the clear (counts and versions only) so doctor needs no network; best-effort.
	if mirror {
		_ = platform.WriteAtomic(filepath.Join(r.eff.StateDir, engine.Name), body, 0o600)
	}

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
		ConfigVersion:   r.eff.ConfigVersion,
		ConfigExpired:   r.eff.ConfigExpired,
		Client:          clientBlock(),
		RunID:           r.runID,
	}, body, r.recipients)
	if err != nil {
		return err
	}

	if r.uploadErr != nil {
		return r.uploadErr
	}
	// The same authorization, validation and PUT as trajectories: no second way to reach the store.
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

// clientBlock is the build identity the ETL groups on, built in one place so objects cannot disagree.
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
