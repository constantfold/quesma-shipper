// Package controlplane handles enrollment, configuration, upload authorization and telemetry.
// It never reports collected payloads, upload cursors or per-object acknowledgements.
// No client is constructed without an endpoint.
package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// maxResponseBytes bounds what the client will read: a larger response is a bug or a hostile server.
const maxResponseBytes = 4 << 20

// Client facts sent on every request, even one the server is about to refuse; OS and boot time are best-effort.
const (
	VersionHeader = "X-Shipper-Version"
	OSHeader      = "X-Shipper-OS"
	BootHeader    = "X-Shipper-Boot"
)

var (
	ErrNotEnrolled        = errors.New("backend: this install is not enrolled")
	ErrUnsupportedVersion = errors.New("backend: server has no config this client can execute") // HTTP 409

	// ErrAuthorizeUnavailable is authorize answering 429 or 5xx: the batch commits nothing and a later run retries it.
	ErrAuthorizeUnavailable = errors.New("backend: upload authorization is unavailable")
)

type Client struct {
	o    Options
	http *http.Client
}

type Options struct {
	Endpoint     string
	InstallID    string
	Organization string
	DeviceKey    ed25519.PrivateKey // signs requests after enrollment
}

// New builds a client. An empty endpoint is an error rather than a no-op: that caller has a bug.
func New(o Options) (*Client, error) {
	if o.Endpoint == "" {
		return nil, errors.New("backend: no endpoint configured")
	}
	o.Endpoint = strings.TrimSuffix(o.Endpoint, "/")
	return &Client{o: o, http: &http.Client{
		// A hung control plane costs one timeout rather than a tick.
		Timeout: 30 * time.Second,
		// Following a redirect would strip the device signature or replay it against a host the operator never named.
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("backend: refusing redirect to %s", req.URL.Host)
		},
	}}, nil
}

// ConfigRequest names the config schema versions this build can execute; never a floor, which can brick a fleet that cannot move.
type ConfigRequest struct {
	AgentVersion   string `json:"agent_version"`
	ConfigVersions []int  `json:"config_versions"`
}

// EnrollRequest is the one-time registration. Exactly one of Invite (single use) or Grant
// (managed, multi-use) is set; omitempty keeps invite enrollments byte-identical for older servers.
type EnrollRequest struct {
	Invite          string `json:"invite,omitempty"`
	Grant           string `json:"grant,omitempty"`
	InstallID       string `json:"install_id"`
	DevicePublicKey string `json:"device_public_key"`
	AgeRecipient    string `json:"age_recipient"` // the PUBLIC half only
	Hostname        string `json:"hostname,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

// EnrollResponse carries the server-assigned organization: an install cannot place itself in another org's subtree.
type EnrollResponse struct {
	Organization string `json:"organization"`
}

// ConfigResponse carries the org's served YAML verbatim; past ExpiresAt a cached copy still collects, stamped config_expired.
type ConfigResponse struct {
	Config    []byte    `json:"config"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var out EnrollResponse
	if err := c.post(ctx, "/v1/enroll", req, &out, false); err != nil {
		return nil, err
	}
	if out.Organization == "" {
		return nil, errors.New("backend: enrollment returned no organization")
	}
	return &out, nil
}

// FetchConfig returns the parsed document beside the raw response, which the cache stores verbatim so
// fields this build does not know survive. A document that does not parse is refused whole.
func (c *Client) FetchConfig(ctx context.Context, req ConfigRequest) (*config.Document, ConfigResponse, error) {
	var out ConfigResponse
	if err := c.post(ctx, "/v1/config", req, &out, true); err != nil {
		return nil, out, err
	}
	doc, err := config.ParseServedDocument(out.Config)
	if err != nil {
		return nil, out, fmt.Errorf("backend: %w", err)
	}
	return doc, out, nil
}

func (c *Client) post(ctx context.Context, path string, body, out any, signed bool) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("backend: encode request: %w", err)
	}
	status, raw, err := c.exchange(ctx, path, "", payload, signed)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK, http.StatusCreated:
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrUnsupportedVersion, strings.TrimSpace(string(raw)))
	case http.StatusUnauthorized, http.StatusForbidden:
		return credentialsRefused(path, status)
	default:
		return fmt.Errorf("backend: %s returned HTTP %d: %s", path, status, reason(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("backend: decode %s response: %w", path, err)
	}
	return nil
}

// exchange sends one JSON POST and returns its status and bounded body. A signed request carries
// a detached signature over preamble+payload; v1 routes sign the body alone and pass "".
func (c *Client) exchange(ctx context.Context, path, preamble string, payload []byte, signed bool) (int, []byte, error) {
	if signed && (c.o.InstallID == "" || c.o.Organization == "" || len(c.o.DeviceKey) == 0) {
		return 0, nil, ErrNotEnrolled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.o.Endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("backend: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(VersionHeader, platform.Current().String())
	req.Header.Set("User-Agent", "trajectory-shipper/"+platform.Current().String())
	if v := platform.OSVersion(); v != "" {
		req.Header.Set(OSHeader, v)
	}
	if b := platform.BootTime(); b != "" {
		req.Header.Set(BootHeader, b)
	}
	if signed {
		// The server scopes by the install id in its authenticated record, never this header, so a wider scope is unrequestable.
		sig := ed25519.Sign(c.o.DeviceKey, append([]byte(preamble), payload...))
		req.Header.Set("Authorization", fmt.Sprintf("Shipper-Device org=%s, install=%s, sig=%s",
			c.o.Organization, c.o.InstallID, EncodeKey(sig)))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("backend: %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("backend: read %s response: %w", path, err)
	}
	return resp.StatusCode, raw, nil
}

// credentialsRefused wraps the sentinel the engine stops the run on.
func credentialsRefused(path string, status int) error {
	return fmt.Errorf("backend: %s refused this install's credentials (HTTP %d): %w", path, status, formats.ErrCredentialsRefused)
}

func reason(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "…"
}
