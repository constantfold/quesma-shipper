// Operational telemetry is forwarded verbatim by the authenticated control plane.
// Include every field the collector needs; downstream cannot add machine identity.
package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"uuid"
)

// TelemetryPath is the one route the telemetry signature is valid for: the control plane builds
// the same preamble from the same literal, so a served path that differs is refused locally.
const TelemetryPath = "/v1/telemetry"

// TelemetryPreamble domain-separates the signature like the v2 upload one: the signed bytes are
// this prefix followed by the body. The path is inside it, so a signature cannot be replayed onto another route.
const TelemetryPreamble = "trajectory-shipper-telemetry-v1\nPOST\n" + TelemetryPath + "\n"

// MaxTelemetryBody is what the control plane accepts; more is refused permanently, so this side checks first.
const MaxTelemetryBody = 1 << 20

// TelemetryRequest is one submission. IssuedAt is the caller's stamp and is the freshness the control plane checks.
type TelemetryRequest struct {
	Schema   int             `json:"schema"`
	BatchID  string          `json:"batch_id"`
	IssuedAt time.Time       `json:"issued_at"`
	Payload  json.RawMessage `json:"payload"`
}

// NewBatchID mints the identifier for one event: the far end deduplicates on it, so a resend presents the same id.
func NewBatchID() string { return uuid.New().String() }

var (
	// ErrTelemetryDisabled says this organization has no collector; the answer cannot change before the next configuration load.
	ErrTelemetryDisabled = errors.New("controlplane: telemetry is disabled for this organization")

	// ErrTelemetryRejected is a submission this control plane will never accept.
	ErrTelemetryRejected = errors.New("controlplane: telemetry submission was rejected")

	// ErrTelemetryUnavailable marks a transient submission failure; the next tick retries.
	ErrTelemetryUnavailable = errors.New("controlplane: telemetry could not be delivered")
)

// SubmitTelemetry posts one event to path, taken from served configuration and resolved against
// the enrolled origin, so a served document cannot point telemetry at a third party.
func (c *Client) SubmitTelemetry(ctx context.Context, path, batchID string, issuedAt time.Time, payload json.RawMessage) error {
	switch {
	case c.installID == "":
		return ErrNotEnrolled
	case path == "":
		return ErrTelemetryDisabled
	case path != TelemetryPath:
		return fmt.Errorf("%w: the signature is only valid for %s, not %q", ErrTelemetryRejected, TelemetryPath, path)
	case batchID == "":
		return errors.New("controlplane: telemetry submission carries no batch_id")
	case issuedAt.IsZero():
		return errors.New("controlplane: telemetry submission carries no issued_at")
	case len(payload) == 0:
		return errors.New("controlplane: telemetry submission carries no payload")
	}
	body, err := json.Marshal(TelemetryRequest{Schema: 1, BatchID: batchID, IssuedAt: issuedAt, Payload: payload})
	if err != nil {
		return fmt.Errorf("controlplane: encode telemetry submission: %w", err)
	}
	if len(body) > MaxTelemetryBody {
		return fmt.Errorf("%w: %d bytes is past the %d limit", ErrTelemetryRejected, len(body), MaxTelemetryBody)
	}

	status, raw, err := c.exchange(ctx, path, TelemetryPreamble, body, true)
	switch {
	case err != nil:
		return err
	case status/100 == 2:
		return nil
	case status == http.StatusForbidden: // disabled for this organization, or this install was revoked
		return ErrTelemetryDisabled
	case status == http.StatusBadRequest, status == http.StatusConflict,
		status == http.StatusRequestEntityTooLarge, status == http.StatusUnprocessableEntity:
		return fmt.Errorf("%w (HTTP %d): %s", ErrTelemetryRejected, status, reason(raw))
	default:
		return fmt.Errorf("%w (HTTP %d): %s", ErrTelemetryUnavailable, status, reason(raw))
	}
}
