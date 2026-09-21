package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// telemetrySigningPrefix is the domain-separating preamble, spelled out here rather than taken from
// the constant it tests, so a silent change to the client fails this rather than redefining it.
const telemetrySigningPrefix = "trajectory-shipper-telemetry-v1\nPOST\n/v1/telemetry\n"

// batchID is any valid uuid: what it is does not matter, only that one value is used throughout.
const batchID = "1fe3a22f-e2a1-4e83-bdaf-61dfd9d1bf30"

type submission struct {
	path          string
	authorization string
	body          []byte
	contentType   string
}

// controlPlane stands in for the control plane, which is what the client talks to: it records what
// arrived and answers with a status. The collector is a different service, one hop further on.
func controlPlane(t *testing.T, status int, answer string) (*httptest.Server, *submission) {
	t.Helper()
	got := &submission{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.path, got.authorization, got.body = r.URL.Path, r.Header.Get("Authorization"), body
		got.contentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if answer != "" {
			_, _ = io.WriteString(w, answer)
		}
	}))
	t.Cleanup(server.Close)
	return server, got
}

func client(t *testing.T, endpoint string) (*controlplane.Client, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	c, err := controlplane.New(controlplane.Options{
		Endpoint:     endpoint,
		InstallID:    fixtureInstallID,
		Organization: "acme",
		DeviceKey:    priv,
	})
	require.NoError(t, err)
	return c, pub
}

func payload() json.RawMessage {
	return json.RawMessage(`{"event":"install_health","hostname":"ci-runner-3"}`)
}

func TestTelemetryRequestContract(t *testing.T) {
	server, got := controlPlane(t, http.StatusNoContent, "")
	c, pub := client(t, server.URL)
	issued := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, c.SubmitTelemetry(context.Background(), "/v1/telemetry", batchID, issued, payload()))

	t.Run("SignatureCoversThePrefixAndTheExactBody", func(t *testing.T) {
		sig := deviceSignature(t, got.authorization, "acme", fixtureInstallID)
		assert.True(t, ed25519.Verify(pub, append([]byte(telemetrySigningPrefix), got.body...), sig))
		assert.False(t, ed25519.Verify(pub, got.body, sig), "body-only signatures must not verify")
		assert.Equal(t, "application/json", got.contentType)
	})
	t.Run("EnvelopeIsExactlyTheContract", func(t *testing.T) {
		assert.JSONEq(t, `{"schema":1,"batch_id":"`+batchID+`",`+
			`"issued_at":"2026-09-18T12:00:00Z","payload":`+string(payload())+`}`, string(got.body))
	})
	t.Run("UsesTheServedPath", func(t *testing.T) {
		assert.Equal(t, "/v1/telemetry", got.path)
	})
}

// Each status has one meaning, and the caller acts on which error came back rather than on a code.
func TestTelemetryStatusMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		want   error
	}{
		"accepted":       {http.StatusNoContent, nil},
		"also accepted":  {http.StatusOK, nil},
		"disabled":       {http.StatusForbidden, controlplane.ErrTelemetryDisabled},
		"invalid":        {http.StatusBadRequest, controlplane.ErrTelemetryRejected},
		"too large":      {http.StatusRequestEntityTooLarge, controlplane.ErrTelemetryRejected},
		"unprocessable":  {http.StatusUnprocessableEntity, controlplane.ErrTelemetryRejected},
		"conflict":       {http.StatusConflict, controlplane.ErrTelemetryRejected},
		"rate limited":   {http.StatusTooManyRequests, controlplane.ErrTelemetryUnavailable},
		"collector down": {http.StatusBadGateway, controlplane.ErrTelemetryUnavailable},
		"upstream slow":  {http.StatusGatewayTimeout, controlplane.ErrTelemetryUnavailable},
		"unprovisioned":  {http.StatusServiceUnavailable, controlplane.ErrTelemetryUnavailable},
	} {
		server, _ := controlPlane(t, tc.status, `{"error":"telemetry_something"}`)
		c, _ := client(t, server.URL)
		err := c.SubmitTelemetry(context.Background(), "/v1/telemetry",
			batchID, time.Now().UTC(), payload())
		assert.ErrorIs(t, err, tc.want, name)
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
		{"NoPathIsDisabledWithoutARequest", "", payload(), controlplane.ErrTelemetryDisabled},
		{"OversizedSubmissionIsRefusedLocally", "/v1/telemetry", big, controlplane.ErrTelemetryRejected},
		{"ServedPathThatIsNotTheProtocolsIsRefused", "/v1/elsewhere", payload(), controlplane.ErrTelemetryRejected},
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
