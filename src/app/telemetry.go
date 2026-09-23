package app

// Install-health telemetry, so an operator learns about a failing machine without walking to it.
// The sealed heartbeat carries the same record; this leaves in the clear through the control plane,
// so it sends less, and each field is chosen rather than copied.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// telemetrySubmitter is an interface so a test can watch what a tick would send.
type telemetrySubmitter interface {
	SubmitTelemetry(ctx context.Context, path, batchID string, issuedAt time.Time, payload json.RawMessage) error
}

// InstallHealthEvent names the event for the collector, which only counts unknown names: a rename goes silent.
const InstallHealthEvent = "install_health"

// maxTelemetryMessage only keeps a pathological message from crowding the envelope; the collector cuts shorter.
const maxTelemetryMessage = 400

// telemetryEvent may grow without a collector release: both ends ignore unknown fields. Hostname is
// here because the body is forwarded verbatim; without it an alert names a machine by a UUID.
type telemetryEvent struct {
	Event string `json:"event"`

	Hostname      string           `json:"hostname,omitempty"`
	At            string           `json:"at,omitempty"`
	ClientVersion string           `json:"client_version,omitempty"`
	Consecutive   int              `json:"consecutive_failures,omitempty"`
	Faults        []telemetryFault `json:"faults,omitempty"`
	LastCrash     *telemetryCrash  `json:"last_crash,omitempty"`
}

// telemetryCrash is projected, not the record's type, so a field added for the sealed heartbeat does
// not start crossing in the clear. Phase is a closed vocabulary, "tick N".
type telemetryCrash struct {
	RunID       string `json:"run_id"`
	Phase       string `json:"phase"`
	Consecutive int    `json:"consecutive,omitempty"`
}

// telemetryFault's Kind comes from the closed set in formats, so the collector groups without parsing prose.
type telemetryFault struct {
	At      string `json:"at"`
	Kind    string `json:"kind"`
	RunID   string `json:"run_id"`
	Message string `json:"message,omitempty"`
}

// SubmitTelemetry sends one install-health event if the organization has a collector. It runs after
// judging, off the upload path, so a slow collector never delays shipping. Fail-open and never
// retried: the next tick carries its own batch id and the same bounded window.
func (r *Runtime) SubmitTelemetry(ctx context.Context) {
	if r.eff.TelemetryEndpoint == "" || r.telemetry == nil || r.telemetryOff {
		return
	}

	// One instant for both stamps, so they agree.
	now := time.Now().UTC()
	batch, payload, err := r.installHealth(now)
	if err == nil {
		err = r.telemetry.SubmitTelemetry(ctx, r.eff.TelemetryEndpoint, batch, now, payload)
	}
	switch {
	case err == nil:
	case errors.Is(err, controlplane.ErrTelemetryDisabled):
		// Off or revoked: nothing changes until the next configuration load.
		r.telemetryOff = true
	default:
		fmt.Fprintf(os.Stderr, "warning: telemetry: %v\n", err)
	}
}

// installHealth mints the batch id with the body, so a resend carries the event's id, not a request's.
func (r *Runtime) installHealth(now time.Time) (batchID string, payload []byte, err error) {
	record := r.failureRecord()
	event := telemetryEvent{
		Event:         InstallHealthEvent,
		Hostname:      r.hostname,
		At:            now.Format(time.RFC3339),
		ClientVersion: r.build.Version,
		Consecutive:   record.ConsecutiveFailures,
	}
	if c := record.LastCrash; c != nil {
		event.LastCrash = &telemetryCrash{RunID: c.RunID, Phase: c.Phase, Consecutive: c.Consecutive}
	}
	event.Faults = make([]telemetryFault, 0, len(record.Recent))
	for _, f := range record.Recent {
		event.Faults = append(event.Faults, telemetryFault{
			At: f.At, Kind: f.Kind, RunID: f.RunID, Message: telemetryMessage(f.Message),
		})
	}
	payload, err = json.Marshal(event)
	if err != nil {
		return "", nil, fmt.Errorf("telemetry: %w", err)
	}
	return controlplane.NewBatchID(), payload, nil
}

// telemetryMessage shortens paths: the username is already a placeholder, but the directory names a
// project or a client, which an alert never needs.
func telemetryMessage(message string) string {
	message = shortenTelemetryPaths(message)
	if len(message) <= maxTelemetryMessage {
		return message
	}
	// Cut from the front: a wrapped error's cause is at the end. The marker counts against the bound.
	const marker = "…"
	tail := message[len(message)-(maxTelemetryMessage-len(marker)):]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return marker + tail
}

// absolutePath needs three segments, so a short system path or a fraction stays; a long route shortening is harmless.
var absolutePath = regexp.MustCompile(`(?:/[^/ \t\n"',;:)]+){3,}`)

// shortenTelemetryPaths keeps the last two segments: which file, not where on the machine it lived.
func shortenTelemetryPaths(message string) string {
	if !strings.Contains(message, "/") {
		return message
	}
	return absolutePath.ReplaceAllStringFunc(message, func(path string) string {
		segments := strings.Split(path, "/")
		return "…/" + strings.Join(segments[len(segments)-2:], "/")
	})
}
