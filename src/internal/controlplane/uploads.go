package controlplane

// V2 upload authorization exchanges a bounded batch of prepared object descriptors for one
// short-lived PUT ticket each. Authorization, not acknowledgment: the local fingerprint document
// stays the only upload-progress authority, and no ticket URL is ever logged.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"uuid"
)

const uploadAuthorizePath = "/v2/uploads/authorize"

// uploadAuthorizePreamble domain-separates the v2 signature: the signed bytes are this exact prefix
// followed by the body, with no canonicalization, byte-identical to the protocol fixture.
const uploadAuthorizePreamble = "trajectory-shipper-upload-authorize-v2\nPOST\n" + uploadAuthorizePath + "\n"

// AuthorizeRequest is one bounded authorization batch. The caller stamps IssuedAt, the freshness the server checks.
type AuthorizeRequest struct {
	WriterID string         `json:"writer_id"`
	IssuedAt time.Time      `json:"issued_at"`
	Objects  []UploadObject `json:"objects"`
}

// UploadObject is one prepared object's descriptor. Size is the exact ciphertext byte count, and
// SourceHash is the manifest's pre-redaction digest, never a checksum of the encrypted PUT body.
type UploadObject struct {
	ObjectID   string         `json:"object_id"`
	Key        string         `json:"key"`
	Size       int64          `json:"size"`
	SourceHash string         `json:"source_hash"`
	Metadata   UploadMetadata `json:"metadata"`
}

// UploadMetadata carries the closed plaintext-metadata allowlist, its json tags in order. source-hash
// and ticket-id are absent by design: the server derives both. A heartbeat sets Kind alone.
type UploadMetadata struct {
	ManifestVersion string `json:"manifest-version,omitempty"`
	SourceID        string `json:"source-id,omitempty"`
	ShippedHash     string `json:"shipped-hash,omitempty"`
	ArtifactClass   string `json:"artifact-class,omitempty"`
	AgentVersion    string `json:"agent-version,omitempty"`
	ShapeSniff      string `json:"shape-sniff,omitempty"`
	Derived         string `json:"derived,omitempty"`
	EnrichStatus    string `json:"enrich-status,omitempty"`
	Kind            string `json:"kind,omitempty"`
}

// AuthorizeResponse is one issued ticket batch.
type AuthorizeResponse struct {
	Tickets []Ticket `json:"tickets"`
}

// Ticket is one bounded PUT capability, usable only after the caller matches it back to the
// prepared object and validates its origin and exact key; this package does neither.
type Ticket struct {
	TicketID        string        `json:"ticket_id"`
	ObjectID        string        `json:"object_id"`
	AlreadyPresent  bool          `json:"already_present,omitempty"`
	Method          string        `json:"method,omitempty"`
	URL             string        `json:"url,omitempty"`
	ExpiresAt       time.Time     `json:"expires_at,omitzero"`
	RequiredHeaders TicketHeaders `json:"required_headers,omitempty"`
	ContentLength   int64         `json:"content_length,omitempty"`

	// ContentLengthSigned reports whether the provider signature covers Content-Length, per ticket.
	ContentLengthSigned bool `json:"content_length_signed,omitempty"`
}

// TicketHeaders is a plain map because each store has its own namespace; upload.ValidateTicket enforces the closed name set.
type TicketHeaders map[string]string

// NewWriterID mints this process's writer identity, audit only. Random per process and never persisted.
func NewWriterID() string { return uuid.New().String() }

// AuthorizeUploads exchanges prepared object descriptors for PUT tickets. 401/403 stops the run
// and 429/5xx retries later: conflating them kills an install on a 429.
func (c *Client) AuthorizeUploads(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	switch {
	case req.WriterID == "":
		return AuthorizeResponse{}, errors.New("backend: authorize request carries no writer_id")
	case req.IssuedAt.IsZero():
		return AuthorizeResponse{}, errors.New("backend: authorize request carries no issued_at")
	case len(req.Objects) == 0:
		return AuthorizeResponse{}, errors.New("backend: authorize request carries no objects")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return AuthorizeResponse{}, fmt.Errorf("backend: encode authorize request: %w", err)
	}
	status, raw, err := c.exchange(ctx, uploadAuthorizePath, uploadAuthorizePreamble, payload, true)
	// The body is quoted only on a failure status: a 200 body holds ticket URLs, which never become a diagnostic.
	switch {
	case err != nil:
		return AuthorizeResponse{}, err
	case status == http.StatusOK:
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return AuthorizeResponse{}, credentialsRefused(uploadAuthorizePath, status)
	case status == http.StatusTooManyRequests, status >= 500:
		return AuthorizeResponse{}, fmt.Errorf("%w (HTTP %d): %s", ErrAuthorizeUnavailable, status, reason(raw))
	default:
		return AuthorizeResponse{}, fmt.Errorf("backend: %s returned HTTP %d: %s", uploadAuthorizePath, status, reason(raw))
	}

	// Unknown response fields are ignored so the server may grow the response; every field the
	// client acts on is validated against the prepared object before a byte leaves.
	var resp AuthorizeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return AuthorizeResponse{}, fmt.Errorf("backend: decode %s response: %w", uploadAuthorizePath, err)
	}
	// The server refuses a batch whole or issues one ticket per object; anything else is a partial authorization.
	if len(resp.Tickets) != len(req.Objects) {
		return AuthorizeResponse{}, fmt.Errorf("backend: %s issued %d tickets for %d objects",
			uploadAuthorizePath, len(resp.Tickets), len(req.Objects))
	}
	for _, t := range resp.Tickets {
		if t.AlreadyPresent && (t.TicketID == "" || t.ObjectID == "" || t.Method != "" || t.URL != "" ||
			!t.ExpiresAt.IsZero() || t.RequiredHeaders != nil || t.ContentLength != 0 || t.ContentLengthSigned) {
			return AuthorizeResponse{}, fmt.Errorf("backend: %s returned an invalid already-present answer for object %q",
				uploadAuthorizePath, t.ObjectID)
		}
	}
	return resp, nil
}
