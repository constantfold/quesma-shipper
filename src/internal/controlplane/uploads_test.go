package controlplane_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

func sampleAuthorizeRequest() controlplane.AuthorizeRequest {
	return controlplane.AuthorizeRequest{WriterID: fixtureWriterID, IssuedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
		Objects: []controlplane.UploadObject{{ObjectID: "trajectory-1", Key: fixtureMirrorKey, Size: 481239, SourceHash: fixtureSourceHash,
			Metadata: controlplane.UploadMetadata{ManifestVersion: "1", SourceID: "claude-code-transcripts", ShippedHash: fixtureShippedHash, ArtifactClass: "trajectory"},
		}},
	}
}

func authorize(t *testing.T, status int, response string) (controlplane.AuthorizeResponse, error) {
	t.Helper()
	server, _ := controlPlane(t, status, response)
	c, _ := client(t, server.URL)
	return c.AuthorizeUploads(context.Background(), sampleAuthorizeRequest())
}

// Only 401 and 403 are refused credentials: an unavailable server mistaken for revocation kills the run for good.
func TestAuthorizeUploadsStatusMapping(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusUnauthorized:        formats.ErrCredentialsRefused,
		http.StatusForbidden:           formats.ErrCredentialsRefused,
		http.StatusTooManyRequests:     controlplane.ErrAuthorizeUnavailable,
		http.StatusServiceUnavailable:  controlplane.ErrAuthorizeUnavailable,
		http.StatusInternalServerError: controlplane.ErrAuthorizeUnavailable,
	} {
		_, err := authorize(t, status, "refused for the test")
		require.ErrorIs(t, err, want, "HTTP %d", status)
		assert.Equal(t, want == formats.ErrCredentialsRefused, errors.Is(err, formats.ErrCredentialsRefused), "HTTP %d", status)
	}
}

// Unknown fields are forward-compatible; partial batches and mixed capabilities are not.
func TestAuthorizeUploadResponses(t *testing.T) {
	ticket := `{"ticket_id":"` + fixtureTicketID + `","object_id":"trajectory-1","already_present":true`
	for _, tc := range []struct {
		name, response, wantError string
	}{
		{"already present", `{"tickets":[` + ticket + `}]}`, ""},
		{"unknown fields", `{"tickets":[` + ticket + `,"future_field":"unknown"}],"future_top_level":1}`, ""},
		{"mixed capability", `{"tickets":[` + ticket + `,"method":"PUT"}]}`, "invalid already-present"},
		{"mismatched batch", `{"tickets":[]}`, "issued 0 tickets for 1 objects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := authorize(t, http.StatusOK, tc.response)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []controlplane.Ticket{{TicketID: fixtureTicketID, ObjectID: "trajectory-1", AlreadyPresent: true}}, resp.Tickets)
		})
	}
}

// Following a redirect would strip the device signature or replay it to a host the operator never named.
func TestAuthorizeUploadsRefusesRedirect(t *testing.T) {
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "https://elsewhere.example.invalid"+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	c, _ := client(t, srv.URL)
	_, err := c.AuthorizeUploads(context.Background(), sampleAuthorizeRequest())
	require.ErrorContains(t, err, "refusing redirect to elsewhere.example.invalid")
	assert.Equal(t, 1, hops)
}

// The guards run before any network call, so a malformed batch cannot reach the control plane.
func TestAuthorizeUploadsRefusesIncompleteRequest(t *testing.T) {
	for field, blank := range map[string]func(*controlplane.AuthorizeRequest){
		"writer_id": func(r *controlplane.AuthorizeRequest) { r.WriterID = "" },
		"issued_at": func(r *controlplane.AuthorizeRequest) { r.IssuedAt = time.Time{} },
		"objects":   func(r *controlplane.AuthorizeRequest) { r.Objects = nil },
	} {
		server, got := controlPlane(t, http.StatusOK, "")
		c, _ := client(t, server.URL)
		req := sampleAuthorizeRequest()
		blank(&req)
		_, err := c.AuthorizeUploads(context.Background(), req)
		require.ErrorContains(t, err, field, "a batch missing %s must be refused by name", field)
		assert.Empty(t, got.path)
	}
}
