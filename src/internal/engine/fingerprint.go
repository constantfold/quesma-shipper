package engine

import (
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Key identifies one fingerprint.
type Key struct {
	SourceID   string
	NativePath string
}

// Fingerprint is what the store remembers about one file.
type Fingerprint struct {
	// Size and mtime are the cheap pre-filter; the content hash is the authority. SourceHash also
	// marks a completed ship: only the post-verified-PUT commit may write it, never a failure path.
	SourceSize  int64
	SourceMTime time.Time
	SourceHash  string

	// Derived entries only.
	Enricher   *EnricherRef
	OutputHash string

	// A parked entry waits for backoff. There is no max-retry: giving up is silent data loss.
	Parked       bool
	LastError    string
	BackoffUntil time.Time

	// Attempts counts consecutive failures on this file, turning retry-every-tick into a backoff.
	Attempts int
}

// EnricherRef identifies the enricher that produced a derived entry: the manifest's own shape,
// which is also this document's wire shape.
type EnricherRef = transforms.EnricherRef

// Document is the whole on-disk state, as read by Peek.
type Document struct {
	InstallID   string
	UpdatedAt   time.Time
	SourceSpecs map[string]string
	Entries     map[Key]Fingerprint
}

// ForeignTo reports whether another install wrote this document. An unstamped one belongs to
// whoever opens it, so an empty id on either side is never foreign.
func (d Document) ForeignTo(installID string) bool {
	return d.InstallID != "" && installID != "" && d.InstallID != installID
}
