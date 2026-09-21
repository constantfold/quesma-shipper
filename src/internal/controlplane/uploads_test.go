package controlplane_test

import (
	"context"
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

	c, _ := client(t, srv.URL)
	return c.AuthorizeUploads(context.Background(), sampleAuthorizeRequest())
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

// Unknown fields are forward-compatible; partial batches and mixed capabilities are not.
func TestAuthorizeUploadResponses(t *testing.T) {
	ticket := alreadyPresentTicketJSON()
	for _, tc := range []struct {
		name, response, wantError string
	}{
		{"already present", `{"tickets":[` + ticket + `]}`, ""},
		{"unknown fields", `{"tickets":[` + strings.TrimSuffix(ticket, "}") +
			`,"future_field":"unknown"}],"future_top_level":1}`, ""},
		{"mixed capability", `{"tickets":[` + strings.TrimSuffix(ticket, "}") +
			`,"method":"PUT"}]}`, "invalid already-present"},
		{"mismatched batch", `{"tickets":[]}`, "issued 0 tickets for 1 objects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := controlPlane(t, http.StatusOK, tc.response)
			c, _ := client(t, server.URL)
			resp, err := c.AuthorizeUploads(context.Background(), sampleAuthorizeRequest())
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []controlplane.Ticket{{
				TicketID: fixtureTicketID, ObjectID: "trajectory-1", AlreadyPresent: true,
			}}, resp.Tickets)
		})
	}
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
			c, _ := client(t, "https://control.example.invalid")
			req := sampleAuthorizeRequest()
			blank(&req)
			_, err := c.AuthorizeUploads(context.Background(), req)
			require.Truef(t, err != nil && strings.Contains(err.Error(), field), "a batch missing %s must be refused by name, got %v", field, err)
		})
	}
}

// Writer ids are minted per process, so two calls never agree.
func TestNewWriterIDIsFresh(t *testing.T) {
	first := controlplane.NewWriterID()
	second := controlplane.NewWriterID()
	require.NotEqualf(t, second, first, "two writer ids agree: %s", first)
	assert.Lenf(t, first, len("00000000-0000-0000-0000-000000000000"), "writer id %q is not a uuid", first)
}
