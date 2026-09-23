// Package app is the composition root: the only layer allowed to know which adapter is which
// (presigned PUT uploads, the Cursor join, launchd supervision). Assembly lives here, printing
// lives in cli: a function here returns a value or an error, never a rendered line.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
	"github.com/QuesmaOrg/quesma-shipper/packaging"
)

// Runtime is everything a flush needs, assembled once.
type Runtime struct {
	eff  *config.Effective
	unit *identity.Unit

	// uploadErr is held rather than returned so `preview` still runs on an install that cannot authorize.
	upload    engine.UploadPort
	uploadErr error

	// telemetry outlives a failed upload port: an install that cannot upload most needs its failures heard.
	telemetry telemetrySubmitter

	// telemetryOff latches for this run when the control plane reports no collector; config keeps provenance.
	telemetryOff bool

	// hostname goes in the event: the control plane signs and forwards the body verbatim.
	hostname string

	log   *auditlog.Log
	build Build

	// recipients is built once so every sealed object has the same readers.
	recipients []age.Recipient

	remote controlplane.Remote

	// env expands enricher database candidates with the same rules catalog roots use.
	env sources.Env

	// OnProgress is the per-file hook a verb registers before flushing; nil is silent.
	OnProgress formats.Progress

	// OnLocked runs once a flush holds the non-blocking store lock; a per-run artifact reset at startup
	// would reset another run's.
	OnLocked func()

	// runID and lastCrash come from the CLI's crash journal; audit entries and heartbeats carry them.
	runID     string
	lastCrash *formats.LastCrash

	// rec caches the failure record while the state dir refuses writes (disk full), so heartbeats still carry it.
	recMu sync.Mutex
	rec   *formats.FailureRecord

	// lastRep lets the stall heartbeat keep per-source health; the watchdog is joined before Judge writes it.
	lastRep formats.Report

	// OnCrashShipped fires once a heartbeat carrying the crash reached the sink; heartbeats fail open,
	// so nothing weaker proves delivery.
	OnCrashShipped func()
	crashOnce      sync.Once

	// hbMu serializes heartbeat PUTs: the object is overwritten in place, and an in-flight stall
	// heartbeat must land before the engine's own.
	hbMu sync.Mutex
}

// SetRunInfo stamps audit entries and heartbeats with the run id; one heartbeat carries the previous run's crash.
func (r *Runtime) SetRunInfo(runID string, lastCrash *formats.LastCrash) {
	r.runID, r.lastCrash = runID, lastCrash
	r.log.SetRunID(runID)
}

func New(build Build) (*Runtime, error) {
	// Ctrl-C stops the startup config fetch; a failed refresh does not stop the run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eff, paths, remote, err := ResolveOnline(ctx)
	if err != nil {
		return nil, err
	}
	return NewFrom(build, eff, paths, remote)
}

// NewFrom builds the runtime from an already resolved config, so doctor does not fetch it twice.
func NewFrom(
	build Build,
	eff *config.Effective,
	paths config.Paths,
	remote controlplane.Remote,
) (*Runtime, error) {
	unit, err := identity.Load(paths.StateDir)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nRun `quesma-shipper login <token>` first (or `quesma-shipper local-dev` without a control\n"+
			"plane): an install needs an identity before it can ship", err)
	}

	recipients, err := recipientsFor(eff, unit)
	if err != nil {
		return nil, err
	}
	log, err := auditlog.Open(paths.StateDir)
	if err != nil {
		return nil, err
	}

	// Assigned only on success: a failed *vendPort would box a typed nil and panic instead of reporting uploadErr.
	var up engine.UploadPort
	var telemetry telemetrySubmitter
	client, upErr := newControlPlaneClient(paths.StateDir)
	if upErr == nil {
		telemetry = client
		var port *vendPort
		if port, upErr = newUploadPort(client, eff); upErr == nil {
			up = port
		}
	}

	env, err := sources.OSEnv()
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	return &Runtime{eff: eff, unit: unit, upload: up, uploadErr: upErr, telemetry: telemetry,
		hostname: hostname, log: log, build: build,
		remote: remote, env: env, recipients: recipients}, nil
}

// recipientsFor refuses rather than seal to fewer readers than the operator configured.
func recipientsFor(eff *config.Effective, unit *identity.Unit) ([]age.Recipient, error) {
	var out []age.Recipient
	if eff.IncludeInstallRecipient {
		out = append(out, unit.Recipient())
	}
	for _, s := range eff.AdditionalRecipients {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("encryption.additional_recipients: %q is not an age X25519 recipient: %w", s, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("the recipient set is empty: policy withheld the install recipient and no additional recipients are configured")
	}
	return out, nil
}

func (r *Runtime) options(dryRun bool) engine.Options {
	return engine.Options{
		Plan:       planFor(r.eff),
		Identity:   r.unit,
		Upload:     r.upload,
		Log:        r.log,
		Registry:   sources.NewRegistry(),
		Enrichers:  Enrichers(),
		Env:        r.env,
		Recipients: r.recipients,
		DryRun:     dryRun,
		Client:     clientBlock(),
		Progress:   r.OnProgress,
		RunID:      r.runID,
	}
}

// Enrichers is the compiled registry, shared with doctor so it cannot drift from the engine; config can only disable.
func Enrichers() *transforms.Registry {
	return transforms.NewRegistry(cursorjoin.New())
}

// Flush is how every path runs, so all share one store flock and cannot interleave.
func (r *Runtime) Flush(ctx context.Context, dryRun bool) (formats.Report, error) {
	return r.flushWith(ctx, dryRun, false)
}

// Drain flushes everything pending on an ephemeral host, bounded by the deadline (a stuck hook), not max_files_per_run.
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

	// A preview never needs the upload port.
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
			// A missing marker makes `status` report NEVER on a healthy install.
			fmt.Fprintf(os.Stderr, "warning: could not stamp the last-run marker: %v\n", markErr)
		}
	}
	return rep, err
}

// WriteHeartbeat publishes discovery health, no transcript bytes, inside the install prefix so erasure takes it.
// `doctor` probes the write path with it: the only state object the protocol authorizes.
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
		// The record may include this very run's judgement.
		FailureRecord: r.failureRecord(),
	})
	body, err := hb.Encode()
	if err != nil {
		return err
	}
	hash := transforms.Hash(body)

	// Mirrored in the clear (counts, never payload bytes) for doctor; best-effort, it must never fail a flush.
	if mirror {
		_ = platform.WriteAtomic(filepath.Join(r.eff.StateDir, engine.Name), body, 0o600)
	}

	// The resolved organization, so one erasure sweep of the subtree takes the heartbeat too.
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
		// Same config fields as every mirror manifest, so no reader special-cases this one.
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
	// The same authorization and PUT as trajectories: no second path to the store for a revocation to miss.
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

// planFor hands the engine values, never the resolver, so a new config key does not touch the engine.
// The repo attributor comes from the catalog alone: marker files answer tracking, not config.
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

// Accessors rather than exported fields: a verb reads the runtime, it never swaps a part of it out.

// Effective is the configuration in force.
func (r *Runtime) Effective() *config.Effective { return r.eff }

// RefreshAbsentRoots returns source ids whose roots now resolve; options() rebuilds the plan each
// flush, so the next tick collects them.
func (r *Runtime) RefreshAbsentRoots() []string { return config.RefreshAbsentRoots(r.eff, r.env) }

// Remote is the outcome of this run's config refresh, so a verb can report a fallback.
func (r *Runtime) Remote() controlplane.Remote { return r.remote }

// Destination describes where objects go, never as a URL: a ticket's path and query are credentials.
func (r *Runtime) Destination() string { return DescribeDestination(r.eff) }

// StateDir is the directory in force, which is not necessarily the default one.
func (r *Runtime) StateDir() string { return r.eff.StateDir }

// AuditLog is exposed so the scheduler can record a panic: a run that died leaves no report.
func (r *Runtime) AuditLog() *auditlog.Log { return r.log }

// Recipients are the public keys objects are encrypted to, as strings: public halves only.
func (r *Runtime) Recipients() []string {
	out := make([]string, 0, len(r.recipients))
	for _, rec := range r.recipients {
		out = append(out, rec.(*age.X25519Recipient).String())
	}
	return out
}

// FilterSources narrows a run to one source on a copy, so the next verb reads the full config.
func (r *Runtime) FilterSources(id string) {
	clone := *r.eff
	clone.Sources = nil
	for _, s := range r.eff.Sources {
		if s.ID == id {
			clone.Sources = append(clone.Sources, s)
		}
	}
	r.eff = &clone
}

// clientBlock is the build identity in every object; the ETL groups on it, so it is built in one place.
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
