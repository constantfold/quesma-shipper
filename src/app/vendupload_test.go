package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

// The classifications the vend port owes the engine: each decides whether a run stops for good,
// stops until the next tick, or asks for one fresh ticket, so each is asserted on its own.

func TestAlreadyPresentCommitsWithoutSpendingACapability(t *testing.T) {
	p := &vendPort{}
	err := p.send(context.Background(), engine.PreparedObject{ObjectID: "trajectory-1"},
		controlplane.Ticket{TicketID: "b1bd1a73-f16d-4a51-aac6-29f1f48b0658", ObjectID: "trajectory-1", AlreadyPresent: true})
	require.NoErrorf(t, err, "already-present answer tried to validate or upload a capability: %v", err)
}

// A refusal kills the install, an outage stops only this run: conflating them turns a rate limit
// into a permanently dead install, so the sentinels must not reach each other.
func TestAuthorizeFailuresKeepRefusalAndUnavailabilityApart(t *testing.T) {
	refused := fmt.Errorf("backend: /v2/uploads/authorize refused this install (HTTP 403): %w",
		formats.ErrCredentialsRefused)
	if got := classifyAuthorize(refused); !errors.Is(got, formats.ErrCredentialsRefused) {
		t.Errorf("a refusal was reclassified as %v", got)
	}
	if got := classifyAuthorize(refused); errors.Is(got, engine.ErrUploadUnavailable) {
		t.Error("a refusal also reads as an unavailable control plane")
	}

	unavailable := fmt.Errorf("%w (HTTP 503)", controlplane.ErrAuthorizeUnavailable)
	got := classifyAuthorize(unavailable)
	assert.ErrorIsf(t, got, engine.ErrUploadUnavailable, "%v was not classified as unavailable: %v", unavailable, got)
	assert.Truef(t, !errors.Is(got, formats.ErrCredentialsRefused), "%v reads as a credentials refusal, which would kill the install", unavailable)

	// Everything else is one batch's failure: no sentinel, so the next run retries it.
	for _, other := range []error{
		errors.New("backend: decode response"),
		errors.New("backend: /v2/uploads/authorize returned HTTP 409"),
	} {
		if got := classifyAuthorize(other); got != other {
			t.Errorf("an unclassified failure was rewritten to %v", got)
		}
	}
}

// Exactly one PUT verdict earns a second authorization inside a run: a store refusal on a ticket
// whose expiry has passed. A refusal on a live ticket must not, or a wrong key would cost two.
func TestOnlyAnExpiredTicketAsksForAnotherAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	p := &vendPort{now: func() time.Time { return now }}

	expired := upload.Ticket{ExpiresAt: now.Add(-time.Second)}
	live := upload.Ticket{ExpiresAt: now.Add(time.Minute)}
	refusal := &upload.StatusError{Status: 403, Reason: "Request has expired"}

	if got := p.classifyPut(refusal, expired); !errors.Is(got, engine.ErrTicketExpired) {
		t.Errorf("a refusal on an expired ticket was classified as %v", got)
	}
	if got := p.classifyPut(refusal, live); errors.Is(got, engine.ErrTicketExpired) {
		t.Error("a refusal on a live ticket asked for a second authorization")
	}
	notFound := &upload.StatusError{Status: 404}
	if got := p.classifyPut(notFound, expired); errors.Is(got, engine.ErrTicketExpired) {
		t.Error("a 404 on an expired ticket was read as an expiry")
	}
	transport := errors.New("connection reset")
	if got := p.classifyPut(transport, expired); got != transport {
		t.Errorf("a transport failure was rewritten to %v", got)
	}
}

func preparedObject(id string) engine.PreparedObject {
	return engine.PreparedObject{
		ObjectID: id, Key: "k" + id, Body: []byte("sealed " + id),
		SourceHash: strings.Repeat("a", 64),
		Metadata:   map[string]string{"source-id": "claude-code-transcripts"},
	}
}

// portAgainst is one vend port whose control plane and store are both fn, so the test sees every
// request the port makes.
func portAgainst(t *testing.T, fn http.HandlerFunc) *vendPort {
	t.Helper()
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	client, err := controlplane.New(controlplane.Options{
		Endpoint:  srv.URL,
		InstallID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301", Organization: "acme",
		DeviceKey: key,
	})
	require.NoError(t, err)
	target, err := upload.NewUploadTarget(upload.TargetSpec{
		Origin: srv.URL, Addressing: upload.PathStyle, PathPrefix: "/b", AllowLoopbackHTTP: true,
	})
	require.NoError(t, err)
	return &vendPort{client: client, uploader: upload.New(), targets: upload.UploadTargetList{target},
		writerID: "writer", now: time.Now}
}

// An object the archive already holds is finished at the answer: no ticket validation and no
// PUT, while the absent one in the same batch is still sent.
func TestAnAlreadyPresentAnswerSkipsThePutAndTheRestStillShips(t *testing.T) {
	var puts []string
	p := portAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts = append(puts, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"tickets":[`+
			`{"ticket_id":"b1bd1a73-f16d-4a51-aac6-29f1f48b0658","object_id":"0","already_present":true},`+
			`{"ticket_id":"b1bd1a73-f16d-4a51-aac6-29f1f48b0659","object_id":"1","method":"PUT",`+
			`"url":"http://%s/b/k1","expires_at":"2099-01-01T00:00:00Z",`+
			`"required_headers":{"x-amz-meta-source-hash":"%s","x-amz-meta-ticket-id":"b1bd1a73-f16d-4a51-aac6-29f1f48b0659",`+
			`"x-amz-meta-source-id":"claude-code-transcripts"},`+
			`"content_length":8,"content_length_signed":true}]}`, r.Host, strings.Repeat("a", 64))
	})

	out := p.AuthorizeAndUpload(context.Background(), []engine.PreparedObject{preparedObject("0"), preparedObject("1")})
	require.Truef(t, len(out) == 2 && errors.Is(out[0], engine.ErrAlreadyPresent) && out[1] == nil, "the batch did not succeed whole: %v", out)
	assert.Truef(t, len(puts) == 1 && puts[0] == "/b/k1", "the port PUT %v, want the absent object alone", puts)
}

// The request metadata set is closed: a name outside it fails the whole batch, because dropping
// it would ship an object whose plaintext metadata disagrees with the manifest sealed inside.
func TestUploadMetadataRefusesAnythingOutsideTheClosedSet(t *testing.T) {
	md, _, err := uploadMetadata(map[string]string{
		"manifest-version": "1",
		"source-id":        "claude-code-transcripts",
		"shipped-hash":     "abc",
		"artifact-class":   "trajectory",
		"derived":          "true",
	})
	require.NoErrorf(t, err, "the manifest's own metadata was refused: %v", err)
	assert.Truef(t, md.ManifestVersion == "1" && md.SourceID == "claude-code-transcripts" && md.Derived == "true", "metadata did not map across: %+v", md)

	// Both are named specifically: "unknown name" would send an operator hunting a typo that is
	// not there.
	for _, name := range []string{"source-hash", "ticket-id"} {
		if _, _, err := uploadMetadata(map[string]string{name: "x"}); err == nil {
			t.Errorf("%s was accepted as client-declarable metadata", name)
		}
	}
	_, _, uploadMetadataErr := uploadMetadata(map[string]string{"native-path": "/home/dev/x.jsonl"})
	assert.Error(t, uploadMetadataErr, "a metadata name outside the closed set was accepted")
}

// agent-version is read out of a transcript, so out of the server's grammar it would fail the
// whole batch for as long as that file exists: one poisoned file killing a source. Dropped loudly.
func TestAnOutOfGrammarAgentVersionIsDroppedRatherThanShipped(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"a control character", "1.0\n0"},
		{"non-ASCII", "1.0.0é"},
		{"over 128 bytes", strings.Repeat("9", 129)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md, dropped, err := uploadMetadata(map[string]string{"agent-version": tc.value})
			require.NoErrorf(t, err, "one bad agent-version failed the whole batch: %v", err)
			assert.Equalf(t, "", md.AgentVersion, "an out-of-grammar agent-version was sent: %q", md.AgentVersion)
			assert.Truef(t, len(dropped) == 1 && strings.Contains(dropped[0], "agent-version"), "the drop was not reported: %v", dropped)
		})
	}

	// The values a real agent writes still travel: this drops the ungrammatical, not the unfamiliar.
	for _, ok := range []string{"1.0.0", "0.2.145-beta+build.7", strings.Repeat("9", 128)} {
		md, dropped, err := uploadMetadata(map[string]string{"agent-version": ok})
		assert.Truef(t, err == nil && md.AgentVersion == ok && len(dropped) == 0, "agent-version %q was dropped: %+v %v %v", ok, md, dropped, err)
	}
}
