package controlplane_test

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

const installID = "0f5a6b3c-1d2e-4f60-8a9b-1c2d3e4f5061"

// fakePlane serves enroll and config exactly as configured, including badly, since refusals are about wrong servers.
type fakePlane struct {
	config       string // replaced between requests to simulate a config push
	expiresAt    time.Time
	configStatus int
	configCalls  int
	lastReq      controlplane.ConfigRequest
	headers      map[string]http.Header // per endpoint, so each is checked rather than whichever came last
}

func newPlane(t *testing.T) (*fakePlane, *httptest.Server) {
	t.Helper()
	p := &fakePlane{config: "org: acme\n", expiresAt: time.Now().Add(24 * time.Hour), headers: map[string]http.Header{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		p.headers[r.URL.Path] = r.Header.Clone()
		var req controlplane.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgeRecipient == "" {
			http.Error(w, "bad enrollment", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(controlplane.EnrollResponse{Organization: "acme"})
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		p.configCalls++
		p.headers[r.URL.Path] = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&p.lastReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.configStatus != 0 {
			http.Error(w, http.StatusText(p.configStatus), p.configStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(controlplane.ConfigResponse{Config: []byte(p.config), ExpiresAt: p.expiresAt})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return p, srv
}

// enrolled returns a record pointing at endpoint, as `quesma-shipper enroll` would have written it.
func enrolled(t *testing.T, endpoint string) *controlplane.Enrollment {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &controlplane.Enrollment{InstallID: installID, Organization: "acme", Endpoint: endpoint,
		DeviceKey: controlplane.EncodeKey(priv), EnrolledAt: "2026-08-03T14:22:51Z"}
}

func client(t *testing.T, endpoint string) (*controlplane.Client, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	c, err := controlplane.New(controlplane.Options{Endpoint: endpoint, InstallID: installID, Organization: "acme", DeviceKey: priv})
	require.NoError(t, err)
	return c, pub
}

type submission struct {
	path, authorization, contentType string
	body                             []byte
}

// controlPlane answers every request with one status and body, and records what arrived.
func controlPlane(t *testing.T, status int, answer string) (*httptest.Server, *submission) {
	t.Helper()
	got := &submission{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.path, got.authorization, got.contentType = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	return server, got
}
