package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// authorizeAgainst spins a server answering every request with one canned reply and returns the
// client's answer for a minimal well-formed batch.
func authorizeAgainst(t *testing.T, handler http.HandlerFunc) (controlplane.AuthorizeResponse, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	client, err := controlplane.New(controlplane.Options{
		Endpoint:     srv.URL,
		InstallID:    fixtureInstallID,
		Organization: "acme",
		DeviceKey:    key,
	})
	require.NoError(t, err)
	return client.AuthorizeUploads(context.Background(), sampleAuthorizeRequest())
}

func alreadyPresentTicketJSON() string {
	return `{"ticket_id":"` + fixtureTicketID + `","object_id":"trajectory-1","already_present":true}`
}

func sampleAuthorizeRequest() controlplane.AuthorizeRequest {
	return controlplane.AuthorizeRequest{
		WriterID: fixtureWriterID,
		IssuedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
		Objects: []controlplane.UploadObject{{
			ObjectID: "trajectory-1", Key: fixtureMirrorKey, Size: 481239,
			SourceHash: fixtureSourceHash,
			Metadata: controlplane.UploadMetadata{
				ManifestVersion: "1", SourceID: "claude-code-transcripts",
				ShippedHash: fixtureShippedHash, ArtifactClass: "trajectory",
			},
		}},
	}
}

// The status table, read the way the design reads it. The distinction that matters is which
// refusals are permanent: only 401 and 403 may reach the engine as refused credentials.
func TestAuthorizeUploadsStatusMapping(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		want        error
		wantRefused bool
	}{
		{name: "401 refuses this install", status: http.StatusUnauthorized,
			want: formats.ErrCredentialsRefused, wantRefused: true},
		{name: "403 refuses this install", status: http.StatusForbidden,
			want: formats.ErrCredentialsRefused, wantRefused: true},
		{name: "429 is a later-run retry", status: http.StatusTooManyRequests,
			want: controlplane.ErrAuthorizeUnavailable},
		{name: "503 is a later-run retry", status: http.StatusServiceUnavailable,
			want: controlplane.ErrAuthorizeUnavailable},
		{name: "500 is a later-run retry", status: http.StatusInternalServerError,
			want: controlplane.ErrAuthorizeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "refused for the test", tc.status)
			})
			require.ErrorIsf(t, err, tc.want, "HTTP %d produced %v, want %v", tc.status, err, tc.want)
			// An unavailable server must never look like a revoked install: that would
			// turn a bounded wait into a permanently dead run.
			assert.Equal(t, errors.Is(err, formats.ErrCredentialsRefused), tc.wantRefused)
		})
	}
}

// A field this build does not know, on the response or inside a ticket, is ignored: the server
// grows the response first, and nothing the client sends comes from a field it did not validate.
func TestAuthorizeUploadsIgnoresUnknownResponseFields(t *testing.T) {
	resp, err := authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ticket := strings.TrimSuffix(alreadyPresentTicketJSON(), "}") + `,"future_field":"unknown"}`
		w.Write([]byte(`{"tickets":[` + ticket + `],"future_top_level":1}`))
	})
	require.NoErrorf(t, err, "an unknown v2 response field was refused: %v", err)
	require.Truef(t, len(resp.Tickets) == 1 && resp.Tickets[0].AlreadyPresent, "want one already-present ticket, got %+v", resp.Tickets)
}

func TestAuthorizeUploadsAcceptsAlreadyPresentAndRejectsMixedCapability(t *testing.T) {
	response, err := authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tickets":[{"ticket_id":"` + fixtureTicketID +
			`","object_id":"trajectory-1","already_present":true}]}`))
	})
	require.Truef(t, err == nil && response.Tickets[0].AlreadyPresent, "valid already-present answer: response=%+v error=%v", response, err)

	_, err = authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tickets":[{"ticket_id":"` + fixtureTicketID +
			`","object_id":"trajectory-1","already_present":true,"method":"PUT"}]}`))
	})
	require.Truef(t, err != nil && strings.Contains(err.Error(), "invalid already-present"), "a mixed already-present capability must be refused, got %v", err)
}

// A batch is authorized whole or not at all, so a short ticket list is a partial authorization
// this client refuses rather than matching up ticket by ticket.
func TestAuthorizeUploadsRejectsMismatchedBatch(t *testing.T) {
	_, err := authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tickets":[]}`))
	})
	require.Truef(t, err != nil && strings.Contains(err.Error(), "issued 0 tickets for 1 objects"), "want an error naming the ticket and object counts, got %v", err)
}

// A redirect is refused rather than followed: following one either strips the device signature
// or replays it against a host the operator never named.
func TestAuthorizeUploadsRefusesRedirect(t *testing.T) {
	var hops int
	_, err := authorizeAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "https://elsewhere.example.invalid"+r.URL.Path, http.StatusTemporaryRedirect)
	})
	require.Error(t, err, "a redirected authorization must fail")
	assert.Equalf(t, 1, hops, "the client made %d requests, a refused redirect is exactly 1", hops)
	assert.Containsf(t, err.Error(), "refusing redirect to elsewhere.example.invalid", "the error should name the host it refused to follow: %v", err)
}

// The guards run before any network call, so a malformed batch cannot reach the control plane.
func TestAuthorizeUploadsRefusesIncompleteRequest(t *testing.T) {
	cases := map[string]func(*controlplane.AuthorizeRequest){
		"writer_id": func(r *controlplane.AuthorizeRequest) { r.WriterID = "" },
		"issued_at": func(r *controlplane.AuthorizeRequest) { r.IssuedAt = time.Time{} },
		"objects":   func(r *controlplane.AuthorizeRequest) { r.Objects = nil },
	}
	for field, blank := range cases {
		t.Run(field, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			client, err := controlplane.New(controlplane.Options{
				Endpoint:     "https://control.example.invalid",
				InstallID:    fixtureInstallID,
				Organization: "acme",
				DeviceKey:    key,
			})
			require.NoError(t, err)
			req := sampleAuthorizeRequest()
			blank(&req)
			_, err = client.AuthorizeUploads(context.Background(), req)
			require.Truef(t, err != nil && strings.Contains(err.Error(), field), "a batch missing %s must be refused by name, got %v", field, err)
		})
	}
}

func TestAuthorizeUploadsAcceptsAnAlreadyPresentTicket(t *testing.T) {
	resp, err := authorizeAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tickets":[` + alreadyPresentTicketJSON() + `]}`))
	})
	require.NoErrorf(t, err, "an already-present answer must decode: %v", err)
	require.Truef(t, len(resp.Tickets) == 1 && resp.Tickets[0].AlreadyPresent, "want one already-present ticket, got %+v", resp.Tickets)
	if resp.Tickets[0].URL != "" || len(resp.Tickets[0].RequiredHeaders) != 0 {
		t.Errorf("an already-present ticket carried a capability: %+v", resp.Tickets[0])
	}
}

// Writer ids are minted per process, so two calls never agree.
func TestNewWriterIDIsFresh(t *testing.T) {
	first := controlplane.NewWriterID()
	second := controlplane.NewWriterID()
	require.NotEqualf(t, second, first, "two writer ids agree: %s", first)
	assert.Lenf(t, first, len("00000000-0000-0000-0000-000000000000"), "writer id %q is not a uuid", first)
}
