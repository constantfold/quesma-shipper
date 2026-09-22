package controlplane_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// fakePlane is a control plane that behaves exactly as configured, including badly: the cases
// worth testing in a client's refusals are all servers that are wrong in a specific way.
type fakePlane struct {
	t *testing.T

	// config is the served document. Replaced between requests to simulate a config push.
	config string

	expiresAt time.Time

	configStatus int

	enrollOrg string

	// counters, so a test can assert on traffic rather than on logs.
	configCalls int

	// lastReq is what the client posted, so the request body can be checked.
	lastReq controlplane.ConfigRequest

	// lastAuth is the Authorization header, so request signing can be checked.
	lastAuth string

	// headersByPath records each endpoint's request headers, so "every request carries the
	// client facts" is checkable per endpoint rather than on whichever came last.
	headersByPath map[string]http.Header
}

func newPlane(t *testing.T) *fakePlane {
	t.Helper()
	return &fakePlane{
		t:             t,
		headersByPath: map[string]http.Header{},
		config:        "org: acme\n",
		expiresAt:     time.Now().Add(24 * time.Hour),
		enrollOrg:     "acme",
	}
}

func (p *fakePlane) start() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		p.headersByPath[r.URL.Path] = r.Header.Clone()
		var req controlplane.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.AgeRecipient == "" {
			http.Error(w, "no age recipient", http.StatusBadRequest)
			return
		}
		writeJSON(w, controlplane.EnrollResponse{Organization: p.enrollOrg})
	})

	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		p.configCalls++
		p.lastAuth = r.Header.Get("Authorization")
		p.headersByPath[r.URL.Path] = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&p.lastReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.configStatus != 0 {
			http.Error(w, http.StatusText(p.configStatus), p.configStatus)
			return
		}
		writeJSON(w, controlplane.ConfigResponse{Config: []byte(p.config), ExpiresAt: p.expiresAt})
	})

	srv := httptest.NewServer(mux)
	p.t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// enrolled returns a record pointing at the plane, as `quesma-shipper enroll` would have written it.
func (p *fakePlane) enrolled(t *testing.T, endpoint, installID string) *controlplane.Enrollment {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &controlplane.Enrollment{
		InstallID:    installID,
		Organization: p.enrollOrg,
		Endpoint:     endpoint,
		DeviceKey:    base64.StdEncoding.EncodeToString(priv),
		EnrolledAt:   controlplane.Now(),
	}
}

func (p *fakePlane) client(t *testing.T, endpoint, install string) *controlplane.Client {
	t.Helper()
	e := p.enrolled(t, endpoint, install)
	c, err := e.Client()
	require.NoError(t, err)
	return c
}

const installID = "0f5a6b3c-1d2e-4f60-8a9b-1c2d3e4f5061"
