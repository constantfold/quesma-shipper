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

// A refusal kills the install and an outage stops one run; the sentinels never wrap each other.
func TestClassifyAuthorize(t *testing.T) {
	refused := fmt.Errorf("backend: refused this install (HTTP 403): %w", formats.ErrCredentialsRefused)
	unavailable := fmt.Errorf("%w (HTTP 503)", controlplane.ErrAuthorizeUnavailable)
	got := classifyAuthorize(refused)
	assert.True(t, errors.Is(got, formats.ErrCredentialsRefused) && !errors.Is(got, engine.ErrUploadUnavailable), got)
	got = classifyAuthorize(unavailable)
	assert.True(t, errors.Is(got, engine.ErrUploadUnavailable) && !errors.Is(got, formats.ErrCredentialsRefused), got)
	for _, other := range []error{errors.New("backend: decode response"), errors.New("backend: HTTP 409")} {
		assert.Equal(t, other, classifyAuthorize(other))
	}
}

// Only a store refusal on an expired ticket earns a second authorization inside a run.
func TestClassifyPut(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	p := &vendPort{now: func() time.Time { return now }}
	expired := upload.Ticket{ExpiresAt: now.Add(-time.Second)}
	live := upload.Ticket{ExpiresAt: now.Add(time.Minute)}
	refusal := &upload.StatusError{Status: 403, Reason: "Request has expired"}

	assert.ErrorIs(t, p.classifyPut(refusal, expired), engine.ErrTicketExpired)
	assert.NotErrorIs(t, p.classifyPut(refusal, live), engine.ErrTicketExpired)
	assert.NotErrorIs(t, p.classifyPut(&upload.StatusError{Status: 404}, expired), engine.ErrTicketExpired)
	transport := errors.New("connection reset")
	assert.Equal(t, transport, p.classifyPut(transport, expired))
}

func preparedObject(id string) engine.PreparedObject {
	return engine.PreparedObject{ObjectID: id, Key: "k" + id, Body: []byte("sealed " + id), SourceHash: strings.Repeat("a", 64),
		Metadata: map[string]string{"source-id": "claude-code-transcripts"}}
}

// portAgainst serves both the control plane and the store from fn, so the test sees every request.
func portAgainst(t *testing.T, fn http.HandlerFunc) *vendPort {
	t.Helper()
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	client, err := controlplane.New(controlplane.Options{Endpoint: srv.URL, InstallID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Organization: "acme", DeviceKey: key})
	require.NoError(t, err)
	target, err := upload.NewUploadTarget(upload.TargetSpec{
		Origin: srv.URL, Addressing: upload.PathStyle, PathPrefix: "/b", AllowLoopbackHTTP: true,
	})
	require.NoError(t, err)
	return &vendPort{client: client, uploader: upload.New(), targets: upload.UploadTargetList{target},
		writerID: "writer", now: time.Now}
}

// An already-present object gets no PUT, while the absent one in the same batch is still sent.
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

// A metadata name outside the closed set fails the batch rather than disagree with the sealed manifest.
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

	// Server-derived names and names outside the closed set are both refused.
	for _, name := range []string{"source-hash", "ticket-id", "native-path"} {
		_, _, err := uploadMetadata(map[string]string{name: "x"})
		assert.Error(t, err, "%s was accepted as client-declarable metadata", name)
	}
}

// An out-of-grammar agent-version is dropped loudly, so one file cannot fail every batch.
func TestAnOutOfGrammarAgentVersionIsDroppedRatherThanShipped(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"1.0\n0", false}, {"1.0.0é", false}, {strings.Repeat("9", 129), false},
		{"1.0.0", true}, {"0.2.145-beta+build.7", true}, {strings.Repeat("9", 128), true},
	} {
		md, dropped, err := uploadMetadata(map[string]string{"agent-version": tc.value})
		require.NoError(t, err, "one agent-version must never fail the whole batch")
		if tc.ok {
			assert.True(t, md.AgentVersion == tc.value && len(dropped) == 0, "%q was dropped: %v", tc.value, dropped)
		} else {
			assert.True(t, md.AgentVersion == "" && len(dropped) == 1 && strings.Contains(dropped[0], "agent-version"),
				"%q: sent %q, reported %v", tc.value, md.AgentVersion, dropped)
		}
	}
}
