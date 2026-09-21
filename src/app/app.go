package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// Runtime is everything a flush needs, assembled once.
type Runtime struct {
	eff  *config.Effective
	unit *identity.Unit

	// upload is the one write path; uploadErr is held rather than returned so `preview` still
	// runs on an install that cannot authorize anything.
	upload    engine.UploadPort
	uploadErr error

	// telemetry outlives a failed upload port: an install that cannot upload is exactly the one
	// whose failures someone should hear about.
	telemetry telemetrySubmitter

	// telemetryOff latches when the control plane says this organization has no collector. Run
	// scoped, not written back into the resolved configuration, which carries provenance.
	telemetryOff bool

	// hostname has to be in the event: the control plane forwards the body verbatim as the bytes it
	// signs, so nothing downstream can add one.
	hostname string

	log   *auditlog.Log
	build Build

	// recipients is built once so every sealed object is encrypted to the same set.
	recipients []age.Recipient

	// remote is the refresh outcome, kept so a verb can report a fallback.
	remote controlplane.Remote

	// env expands an enricher's declared database candidates, with the same rules catalog roots use.
	env sources.Env

	// OnProgress is the per-file hook a verb registers before flushing; rendering is CLI-owned.
	// Nil (the default) is silent.
	OnProgress formats.Progress

	// OnLocked runs once a flush holds the store lock. The lock is non-blocking, so a verb resets a
	// per-run artifact from here, not at startup, where it would reset another's.
	OnLocked func()

	// runID and lastCrash come from the CLI's crash journal; audit entries and heartbeats carry them.
	runID     string
	lastCrash *formats.LastCrash

	// rec caches the failure record while the state dir refuses writes (disk full), so the next
	// heartbeat still carries the judgement; a successful write drops it.
	recMu sync.Mutex
	rec   *formats.FailureRecord

	// lastRep is the last completed tick's report, reused by the stall heartbeat so a stalled
	// install does not blank its own per-source health. Judge writes it, the next tick's watchdog
	// reads it; the two never overlap (the watchdog is joined before judging).
	lastRep formats.Report

	// OnCrashShipped fires once, when a heartbeat CARRYING the crash report reached the sink; the
	// heartbeat fails open, so nothing weaker proves delivery.
	OnCrashShipped func()
	crashOnce      sync.Once

	// hbMu serializes heartbeat PUTs: the remote object is overwritten in place, and a stall
	// heartbeat still in flight must land BEFORE the engine's own, not over it.
	hbMu sync.Mutex
}

// The run id lands on every audit entry and heartbeat; the previous run's death rides one out.
func (r *Runtime) SetRunInfo(runID string, lastCrash *formats.LastCrash) {
	r.runID, r.lastCrash = runID, lastCrash
	r.log.SetRunID(runID)
}

func New(build Build) (*Runtime, error) {
	// Cancellable, so Ctrl-C during the startup config fetch stops it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The collecting verbs refresh the remote layer first; a failed refresh does not stop the run.
	eff, paths, remote, err := ResolveOnline(ctx)
	if err != nil {
		return nil, err
	}
	return NewFrom(build, eff, paths, remote)
}

// NewFrom builds the runtime from an ALREADY resolved config, so a verb that has resolved once
// (doctor) does not pay for a second config fetch.
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

	// Held rather than returned so `preview` keeps working on an install that has no control
	// plane. The port stays interface-typed and is assigned only on success: a failed *vendPort
	// would box a typed nil and panic on first use instead of reporting uploadErr. The client is
	// built first and kept even when the port is not.
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

// recipientsFor composes the encryption set from the identity unit and the resolved config:
// refusing beats sealing to fewer readers than the operator configured.
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

// Effective is the configuration in force.
func (r *Runtime) Effective() *config.Effective { return r.eff }

// RefreshAbsentRoots re-picks the roots that did not resolve at startup and reports the source ids
// that now do. The scheduler calls it before each tick: options() rebuilds the plan from r.eff
// every flush, so a root found here is collected by the tick that follows.
func (r *Runtime) RefreshAbsentRoots() []string { return config.RefreshAbsentRoots(r.eff, r.env) }

// Remote is the outcome of this run's config refresh, so a verb can report a fallback.
func (r *Runtime) Remote() controlplane.Remote { return r.remote }

// Destination describes where objects go. A description, never a URL: a ticket's path and query
// are credentials that must not reach a printed line.
func (r *Runtime) Destination() string { return DescribeDestination(r.eff) }

// StateDir is the directory in force, which is not necessarily the default one.
func (r *Runtime) StateDir() string { return r.eff.StateDir }

// AuditLog is the append-only record of what this install decided. Exposed so the scheduler loop
// can record a panic: a run that died leaves no report.
func (r *Runtime) AuditLog() *auditlog.Log { return r.log }

// Recipients are the public keys objects are encrypted to, as strings: public halves only.
func (r *Runtime) Recipients() []string {
	out := make([]string, 0, len(r.recipients))
	for _, rec := range r.recipients {
		out = append(out, rec.(*age.X25519Recipient).String())
	}
	return out
}

// FilterSources narrows a run to one source, on a copy: narrowing a view must not mutate the
// configuration the next verb reads.
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
