package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
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

	// uploadErr is held rather than returned so `preview` still runs on an install that cannot authorize.
	upload    engine.UploadPort
	uploadErr error

	// telemetry outlives a failed upload port: that install is the one whose failures matter most.
	telemetry    telemetrySubmitter
	telemetryOff bool // latched for this run when the control plane says there is no collector

	// hostname goes in the event because the control plane forwards the signed body verbatim.
	hostname   string
	log        *auditlog.Log
	build      Build
	recipients []age.Recipient // built once so every sealed object has the same readers
	remote     controlplane.Remote
	env        sources.Env

	// OnProgress is the per-file hook a verb registers before flushing; nil is silent.
	OnProgress formats.Progress

	// OnLocked runs once a flush holds the non-blocking store lock, so a verb resets per-run
	// artifacts there rather than at startup, where it would reset another process's.
	OnLocked func()

	runID     string
	lastCrash *formats.LastCrash

	// rec caches the failure record while the state dir refuses writes, so heartbeats still carry it.
	recMu sync.Mutex
	rec   *formats.FailureRecord

	// lastRep is the last completed tick's report, reused by the stall heartbeat; the watchdog is
	// joined before judging, so the two never overlap.
	lastRep formats.Report

	// OnCrashShipped fires once, when a heartbeat carrying the crash report reached the sink.
	OnCrashShipped func()
	crashOnce      sync.Once

	// hbMu serializes heartbeat PUTs so a stall heartbeat in flight lands before the engine's own.
	hbMu sync.Mutex
}

// SetRunInfo stamps audit entries and heartbeats with the run id and the previous run's crash.
func (r *Runtime) SetRunInfo(runID string, lastCrash *formats.LastCrash) {
	r.runID, r.lastCrash = runID, lastCrash
	r.log.SetRunID(runID)
}

// New refreshes the remote layer first; Ctrl-C stops the fetch, a failed refresh does not stop the run.
func New(build Build) (*Runtime, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eff, paths, remote, err := ResolveOnline(ctx)
	if err != nil {
		return nil, err
	}
	return NewFrom(build, eff, paths, remote)
}

// NewFrom builds the runtime from an already resolved config, so doctor does not fetch it twice.
func NewFrom(build Build, eff *config.Effective, paths config.Paths, remote controlplane.Remote) (*Runtime, error) {
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

	// The port is assigned only on success: a failed *vendPort would box a typed nil and panic on
	// first use instead of reporting uploadErr. The client is kept even when the port is not.
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

func (r *Runtime) Effective() *config.Effective { return r.eff }

// RefreshAbsentRoots re-picks roots that did not resolve at startup and reports the source ids that
// now do; every flush rebuilds the engine options, so the next tick collects them.
func (r *Runtime) RefreshAbsentRoots() []string { return config.RefreshAbsentRoots(r.eff, r.env) }

func (r *Runtime) Remote() controlplane.Remote { return r.remote }

func (r *Runtime) Destination() string { return DescribeDestination(r.eff) }

func (r *Runtime) StateDir() string { return r.eff.StateDir }

// AuditLog is exposed so the scheduler loop can record a panic: a run that died leaves no report.
func (r *Runtime) AuditLog() *auditlog.Log { return r.log }

func (r *Runtime) Recipients() []string {
	out := make([]string, 0, len(r.recipients))
	for _, rec := range r.recipients {
		out = append(out, rec.(*age.X25519Recipient).String())
	}
	return out
}

// FilterSources narrows a run to one source on a copy, leaving the configuration others read intact.
func (r *Runtime) FilterSources(id string) {
	clone := *r.eff
	clone.Sources = slices.DeleteFunc(slices.Clone(r.eff.Sources), func(s config.ResolvedSource) bool { return s.ID != id })
	r.eff = &clone
}
