package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// An absolute path in a fault message names the directory a file sat in, which on a working machine
// names a project or a client. The last two segments say which file, which is all an alert needs.
func TestAbsolutePathsAreShortenedOnTheWayOut(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"a project path": {
			"config: /Users/USER/projects/acme-client/.quesma/config.yaml: parse document",
			"config: …/.quesma/config.yaml: parse document",
		},
		"two paths in one message": {
			"copy /var/lib/quesma/state/a.json to /home/USER/work/b.json",
			"copy …/state/a.json to …/work/b.json",
		},
		"a short path is left alone": {"read /etc/hosts failed", "read /etc/hosts failed"},
		"a bare slash is left alone": {"ratio 3/4 exceeded", "ratio 3/4 exceeded"},
		"a route is shortened too":   {"backend: /v2/uploads/authorize: 503", "backend: …/uploads/authorize: 503"},
	} {
		assert.Equal(t, tc.want, shortenTelemetryPaths(tc.in), name)
	}
}

// A wrapped error's cause is at the end, so a message past the bound keeps its tail.
func TestALongMessageKeepsItsCause(t *testing.T) {
	message := strings.Repeat("wrapped: ", 200) + "connection refused"
	got := telemetryMessage(message)
	require.Truef(t, len(got) <= maxTelemetryMessage, "message is %d bytes, the bound is %d", len(got), maxTelemetryMessage)
	assert.Truef(t, strings.HasSuffix(got, "connection refused"), "the cause was cut off: %q", got)
}

// telemetryRuntime builds the least installHealth needs: a state directory holding a failure record.
func telemetryRuntime(t *testing.T, record formats.FailureRecord) *Runtime {
	t.Helper()
	dir := t.TempDir()
	body, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, lastFailureFile), body, 0o600))
	return &Runtime{
		eff:      &config.Effective{StateDir: dir, TelemetryEndpoint: "/v1/telemetry"},
		hostname: "ci-runner-3",
		build:    Build{Version: "0.0.3"},
	}
}

// The collector reads these field names from the signed body verbatim.
func TestTheEventCarriesTheFieldsTheCollectorReads(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{
		ConsecutiveFailures: 2,
		Recent: []formats.FailureEvent{{
			At: "2026-09-18T11:58:00Z", Kind: formats.FailureTick, RunID: "r1",
			Message: "backend: 503",
		}},
	})
	// The CLI journal supplies the crash independently of the failure file.
	r.lastCrash = &formats.LastCrash{RunID: "r0", Phase: "tick 1", Consecutive: 1}

	batch, body, err := r.installHealth(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	require.NotEmpty(t, batch)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	for field, want := range map[string]any{
		"event":                InstallHealthEvent,
		"hostname":             "ci-runner-3",
		"client_version":       "0.0.3",
		"consecutive_failures": float64(2),
	} {
		assert.Equal(t, want, got[field], field)
	}
	assert.Equal(t, []any{map[string]any{
		"kind": "tick_failed", "run_id": "r1", "at": "2026-09-18T11:58:00Z", "message": "backend: 503",
	}}, got["faults"])
	assert.Equal(t, map[string]any{"run_id": "r0", "phase": "tick 1", "consecutive": float64(1)}, got["last_crash"])
}

func TestHealthyEventNamesTheMachineAndBatch(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	batch, body, err := r.installHealth(time.Now().UTC())
	require.NoError(t, err)
	assert.Contains(t, string(body), `"hostname":"ci-runner-3"`)
	assert.NotEmpty(t, batch)
}

type stub struct {
	calls int
	err   error
}

func (s *stub) SubmitTelemetry(context.Context, string, string, time.Time, json.RawMessage) error {
	s.calls++
	return s.err
}

// Only an explicit disablement latches off; resolved configuration keeps its provenance.
func TestTelemetrySubmissionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint string
		err            error
		calls          int
		off            bool
	}{
		{"disabled", "/v1/telemetry", controlplane.ErrTelemetryDisabled, 1, true},
		{"recoverable failure", "/v1/telemetry", errors.New("collector unreachable"), 2, false},
		{"healthy", "/v1/telemetry", nil, 2, false},
		{"no endpoint", "", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := telemetryRuntime(t, formats.FailureRecord{})
			r.eff.TelemetryEndpoint = tc.endpoint
			s := &stub{err: tc.err}
			r.telemetry = s
			r.SubmitTelemetry(context.Background())
			r.SubmitTelemetry(context.Background())
			assert.Equal(t, tc.calls, s.calls)
			assert.Equal(t, tc.off, r.telemetryOff)
			assert.Equal(t, tc.endpoint, r.eff.TelemetryEndpoint)
		})
	}
}
