package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// batchID is any valid uuid: only that one value is used throughout matters.
const batchID = "1fe3a22f-e2a1-4e83-bdaf-61dfd9d1bf30"

var telemetryPayload = json.RawMessage(`{"event":"install_health","hostname":"ci-runner-3"}`)

func TestTelemetryRequestContract(t *testing.T) {
	server, got := controlPlane(t, http.StatusNoContent, "")
	c, pub := client(t, server.URL)
	issued := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, c.SubmitTelemetry(context.Background(), "/v1/telemetry", batchID, issued, telemetryPayload))

	// The prefix is spelled out rather than taken from the constant, so a silent change to the client fails here.
	sig := deviceSignature(t, got.authorization, "acme", installID)
	assert.True(t, ed25519.Verify(pub, append([]byte("trajectory-shipper-telemetry-v1\nPOST\n/v1/telemetry\n"), got.body...), sig))
	assert.False(t, ed25519.Verify(pub, got.body, sig), "body-only signatures must not verify")
	assert.Equal(t, "application/json", got.contentType)
	assert.Equal(t, "/v1/telemetry", got.path)
	assert.JSONEq(t, `{"schema":1,"batch_id":"`+batchID+`","issued_at":"2026-09-18T12:00:00Z","payload":`+
		string(telemetryPayload)+`}`, string(got.body))
}

// Each status has one meaning, and the caller acts on which error came back rather than on a code.
func TestTelemetryStatusMapping(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusNoContent:             nil,
		http.StatusOK:                    nil,
		http.StatusForbidden:             controlplane.ErrTelemetryDisabled,
		http.StatusBadRequest:            controlplane.ErrTelemetryRejected,
		http.StatusRequestEntityTooLarge: controlplane.ErrTelemetryRejected,
		http.StatusUnprocessableEntity:   controlplane.ErrTelemetryRejected,
		http.StatusConflict:              controlplane.ErrTelemetryRejected,
		http.StatusTooManyRequests:       controlplane.ErrTelemetryUnavailable,
		http.StatusBadGateway:            controlplane.ErrTelemetryUnavailable,
		http.StatusGatewayTimeout:        controlplane.ErrTelemetryUnavailable,
		http.StatusServiceUnavailable:    controlplane.ErrTelemetryUnavailable,
	} {
		server, _ := controlPlane(t, status, `{"error":"telemetry_something"}`)
		c, _ := client(t, server.URL)
		err := c.SubmitTelemetry(context.Background(), "/v1/telemetry", batchID, time.Now().UTC(), telemetryPayload)
		assert.ErrorIs(t, err, want, "HTTP %d", status)
	}
}

func TestTelemetryRefusesLocally(t *testing.T) {
	big, err := json.Marshal(map[string]string{"event": strings.Repeat("x", controlplane.MaxTelemetryBody)})
	require.NoError(t, err)
	for _, tc := range []struct {
		name, path string
		payload    json.RawMessage
		want       error
	}{
		{"NoPathIsDisabledWithoutARequest", "", telemetryPayload, controlplane.ErrTelemetryDisabled},
		{"OversizedSubmissionIsRefusedLocally", "/v1/telemetry", big, controlplane.ErrTelemetryRejected},
		{"ServedPathThatIsNotTheProtocolsIsRefused", "/v1/elsewhere", telemetryPayload, controlplane.ErrTelemetryRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, got := controlPlane(t, http.StatusNoContent, "")
			c, _ := client(t, server.URL)
			err := c.SubmitTelemetry(context.Background(), tc.path, batchID, time.Now().UTC(), tc.payload)
			require.ErrorIs(t, err, tc.want)
			assert.Empty(t, got.path, "locally rejected submissions must not send a request")
		})
	}
}
