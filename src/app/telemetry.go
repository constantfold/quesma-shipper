// Telemetry reports selected operational facts in cleartext through the control plane.
// The encrypted heartbeat carries the fuller failure record.
package app

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

// The collector counts rather than renders an unrecognised event name, so a rename goes silent.
const InstallHealthEvent = "install_health"

// maxTelemetryMessage only keeps a pathological message from crowding the envelope.
const maxTelemetryMessage = 400

// telemetryEvent matches the collector's field names; unknown fields are ignored at both ends.
type telemetryEvent struct {
	Event string `json:"event"`

	Hostname      string           `json:"hostname,omitempty"`
	At            string           `json:"at,omitempty"`
	ClientVersion string           `json:"client_version,omitempty"`
	Consecutive   int              `json:"consecutive_failures,omitempty"`
	Faults        []telemetryFault `json:"faults,omitempty"`
	LastCrash     *telemetryCrash  `json:"last_crash,omitempty"`
}

// telemetryCrash is projected, so a new field on the sealed heartbeat's type never crosses in the clear.
type telemetryCrash struct {
	RunID       string `json:"run_id"`
	Phase       string `json:"phase"`
	Consecutive int    `json:"consecutive,omitempty"`
}

type telemetryFault struct {
	At      string `json:"at"`
	Kind    string `json:"kind"`
	RunID   string `json:"run_id"`
	Message string `json:"message,omitempty"`
}

// SubmitTelemetry fails open; the next tick sends a new batch rather than retrying this one.
func (r *Runtime) SubmitTelemetry(ctx context.Context) {
	if r.eff.TelemetryEndpoint == "" || r.telemetry == nil || r.telemetryOff {
		return
	}

	now := time.Now().UTC()
	batch, payload, err := r.installHealth(now)
	if err == nil {
		err = r.telemetry.SubmitTelemetry(ctx, r.eff.TelemetryEndpoint, batch, now, payload)
	}
	switch {
	case err == nil:
	case errors.Is(err, controlplane.ErrTelemetryDisabled):
		r.telemetryOff = true // nothing changes until the next configuration load
	default:
		fmt.Fprintf(os.Stderr, "warning: telemetry: %v\n", err)
	}
}

// installHealth mints the batch id with the body, so the id names the event rather than the request.
func (r *Runtime) installHealth(now time.Time) (batchID string, payload []byte, err error) {
	record := r.failureRecord()
	event := telemetryEvent{Event: InstallHealthEvent, Hostname: r.hostname, At: now.Format(time.RFC3339),
		ClientVersion: r.build.Version, Consecutive: record.ConsecutiveFailures}
	if c := record.LastCrash; c != nil {
		event.LastCrash = &telemetryCrash{RunID: c.RunID, Phase: c.Phase, Consecutive: c.Consecutive}
	}
	event.Faults = make([]telemetryFault, 0, len(record.Recent))
	for _, f := range record.Recent {
		event.Faults = append(event.Faults, telemetryFault{At: f.At, Kind: f.Kind, RunID: f.RunID, Message: telemetryMessage(f.Message)})
	}
	payload, err = json.Marshal(event)
	if err != nil {
		return "", nil, fmt.Errorf("telemetry: %w", err)
	}
	return controlplane.NewBatchID(), payload, nil
}

// telemetryMessage shortens paths, which on a working machine name a project or a client.
func telemetryMessage(message string) string {
	message = shortenTelemetryPaths(message)
	if len(message) <= maxTelemetryMessage {
		return message
	}
	// Cut from the front, since a wrapped error's cause is at the end, and off any split rune.
	const marker = "…"
	tail := message[len(message)-(maxTelemetryMessage-len(marker)):]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return marker + tail
}

// absolutePath is three or more slash-prefixed segments, leaving short system paths and fractions.
var absolutePath = regexp.MustCompile(`(?:/[^/ \t\n"',;:)]+){3,}`)

// shortenTelemetryPaths keeps the last two segments of any absolute path.
func shortenTelemetryPaths(message string) string {
	if !strings.Contains(message, "/") {
		return message
	}
	return absolutePath.ReplaceAllStringFunc(message, func(path string) string {
		segments := strings.Split(path, "/")
		return "…/" + strings.Join(segments[len(segments)-2:], "/")
	})
}
