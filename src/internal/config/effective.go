package config

import (
	"fmt"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// ResolvedSource is sources.Resolved, aliased because this is the package that produces one.
type ResolvedSource = sources.Resolved

// Effective is the resolved configuration: the compiled ceiling, narrowed by every config layer in precedence order.
type Effective struct {
	ConfigVersion int

	// OrganizationID is the organization= key segment; standalone installs write the placeholder "default".
	OrganizationID string

	// ConfigExpired says the remote layer in force is a cached one past expiry; expiry cannot widen scope.
	ConfigExpired bool

	Schedule string

	// DrainDeadline bounds `run --once --drain` and the SIGTERM drain.
	DrainDeadline time.Duration

	StateDir       string
	MaxFilesPerRun int
	Sources        []ResolvedSource

	// Catalog is the compiled catalog the sources were resolved from, so no verb parses it twice.
	Catalog *sources.Compiled

	// UploadTargets are the origins a presigned upload ticket may name. Empty means unpinned.
	UploadTargets []UploadTarget

	RulePacks      []string
	SecretKeyNames []string
	StructuralEx   map[string][]string
	Deny           *sources.List

	AdditionalRecipients    []string
	IncludeInstallRecipient bool

	// AutoupdateEnabled says a released build may replace itself at daemon startup; dev builds never self-update.
	AutoupdateEnabled bool

	// TelemetryEndpoint is the control-plane path telemetry is submitted to; empty means off.
	TelemetryEndpoint string

	// Provenance attributes every value to the layer that set it, for `config show --with-provenance`.
	Provenance map[string]Origin
}

// Origin is where one value came from; Derived marks a value computed rather than configured.
type Origin struct {
	Layer   Layer
	Derived bool
}

// SinkAdapter names the one write path. It is compiled in, and a send: block in a served document is discarded.
const SinkAdapter = "vend"

// Input is everything a resolution needs; the remote layer arrives in Layers as LayerRemote.
type Input struct {
	Catalog *sources.Compiled
	Layers  []LayeredDocument

	// ConfigExpired is set by the caller when the remote layer came from a stale cache; Resolve has no clock.
	ConfigExpired bool
	Env           sources.Env
	StateDir      string
}

// RejectionError is a config refusal. A rejected config is never partially applied: collection continues under the last valid one.
type RejectionError struct {
	Layer  Layer
	Field  string
	Reason string
}

func (e *RejectionError) Error() string {
	return fmt.Sprintf("config rejected: %s (set by the %s layer): %s", e.Field, e.Layer, e.Reason)
}

// reject refuses field, blaming the layer that set it.
func (e *Effective) reject(field, format string, args ...any) error {
	return &RejectionError{e.Provenance[field].Layer, field, fmt.Sprintf(format, args...)}
}

func (e *Effective) setOrigin(field string, l Layer) {
	e.Provenance[field] = Origin{Layer: l}
}
