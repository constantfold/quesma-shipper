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
		"a short path is left alone": {
			"read /etc/hosts failed",
			"read /etc/hosts failed",
		},
		"a bare slash is left alone": {
			"ratio 3/4 exceeded",
			"ratio 3/4 exceeded",
		},
		"a route is shortened too": {
			"backend: /v2/uploads/authorize: 503",
			"backend: …/uploads/authorize: 503",
		},
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

// The field names are the contract with the collector. It reads them by name, so a rename here goes
// silent rather than loud, and this is the only place that would notice.
func TestTheEventCarriesTheFieldsTheCollectorReads(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{
		ConsecutiveFailures: 2,
		Recent: []formats.FailureEvent{{
			At: "2026-09-18T11:58:00Z", Kind: formats.FailureTick, RunID: "r1",
			Message: "backend: 503",
		}},
	})
	// The crash is the CLI's, read from the journal at startup, not something the failure file
	// carries: failureRecord overwrites what is on disk with it.
	r.lastCrash = &formats.LastCrash{RunID: "r0", Phase: "tick 1", Consecutive: 1}

	_, body, err := r.installHealth(time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	for field, want := range map[string]any{
		"event":                InstallHealthEvent,
		"hostname":             "ci-runner-3",
		"client_version":       "0.0.3",
		"consecutive_failures": float64(2),
	} {
		assert.Truef(t, got[field] == want, "%s = %v, want %v", field, got[field], want)
	}
	faults, ok := got["faults"].([]any)
	if !ok || len(faults) != 1 {
		t.Fatalf("faults = %v", got["faults"])
	}
	fault := faults[0].(map[string]any)
	for field, want := range map[string]any{"kind": "tick_failed", "run_id": "r1", "at": "2026-09-18T11:58:00Z"} {
		assert.Truef(t, fault[field] == want, "fault %s = %v, want %v", field, fault[field], want)
	}
	if _, ok := got["last_crash"]; !ok {
		t.Error("the crash was dropped")
	}
}

// The machine's name has to be in the event: the control plane forwards this body verbatim as the
// bytes it signs, so nothing downstream can add one.
func TestTheEventNamesTheMachine(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	_, body, err := r.installHealth(time.Now().UTC())
	require.NoError(t, err)
	require.Containsf(t, string(body), `"hostname":"ci-runner-3"`, "the event does not name the machine: %s", body)
}

// The identity the far end deduplicates on belongs to the event, so the two arrive together and a
// resend of the same event can present the same id.
func TestTheEventCarriesItsOwnBatchIdentity(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	batch, _, err := r.installHealth(time.Now().UTC())
	require.NoError(t, err)
	require.NotEqual(t, "", batch, "the event has no batch identity")
}

type stub struct {
	calls int
	err   error
}

func (s *stub) SubmitTelemetry(context.Context, string, string, time.Time, json.RawMessage) error {
	s.calls++
	return s.err
}

// A disabled organization is not a failure and not worth asking about again: the answer cannot
// change until configuration is loaded, which is the next process.
func TestDisabledStopsAskingForTheRestOfTheRun(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	s := &stub{err: controlplane.ErrTelemetryDisabled}
	r.telemetry = s

	r.SubmitTelemetry(context.Background())
	r.SubmitTelemetry(context.Background())

	require.Equalf(t, 1, s.calls, "asked %d times after being told it is disabled", s.calls)
	// The latch is the runtime's. Resolved configuration carries provenance and is what `config
	// show` reports, so a network answer must not rewrite it.
	assert.Equal(t, "/v1/telemetry", r.eff.TelemetryEndpoint, "a 403 rewrote the resolved configuration")
	assert.True(t, r.telemetryOff, "the run did not latch off")
}

// Everything else is reported and shrugged off: telemetry is how someone hears about a problem and
// must never become one.
func TestOtherFailuresDoNotStopLaterSubmissions(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	s := &stub{err: errors.New("collector unreachable")}
	r.telemetry = s

	r.SubmitTelemetry(context.Background())
	r.SubmitTelemetry(context.Background())

	require.Equalf(t, 2, s.calls, "stopped after a recoverable failure: %d calls", s.calls)
}

// An install whose organization has no collector sends nothing at all.
func TestNoEndpointSendsNothing(t *testing.T) {
	r := telemetryRuntime(t, formats.FailureRecord{})
	r.eff.TelemetryEndpoint = ""
	s := &stub{}
	r.telemetry = s

	r.SubmitTelemetry(context.Background())
	require.Equal(t, 0, s.calls, "submitted for an organization with no collector")
}
