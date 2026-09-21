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

	// ConfigExpired says the remote layer in force is a cached one past expiry; collection continues, expiry cannot widen scope.
	ConfigExpired bool

	Schedule string

	// DrainDeadline bounds `run --once --drain` and the SIGTERM drain, so an exit hook cannot block forever having flushed nothing.
	DrainDeadline time.Duration

	StateDir       string
	MaxFilesPerRun int
	Sources        []ResolvedSource

	// Catalog is the compiled source catalog the sources above were resolved from; the repo
	// attributor and family display names derive from it, so no verb parses it twice.
	Catalog *sources.Compiled

	// UploadTargets pins the origins a presigned upload ticket may name. Empty means unpinned; a bad entry is still refused.
	UploadTargets []UploadTarget

	RulePacks      []string
	SecretKeyNames []string
	StructuralEx   map[string][]string
	Deny           *sources.List

	// AdditionalRecipients are age public keys every object is encrypted to besides the install's own, kept as strings.
	AdditionalRecipients []string

	// IncludeInstallRecipient keeps the install's own key in the recipient set; withholding it requires another recipient.
	IncludeInstallRecipient bool

	// AutoupdateEnabled says a released build may replace itself at daemon startup; dev builds never self-update.
	AutoupdateEnabled bool

	// TelemetryEndpoint is the control-plane path telemetry is submitted to, empty for an
	// organization with no collector. Empty is the default, so telemetry is off unless served on.
	TelemetryEndpoint string

	// Provenance attributes every value to the layer that set it, for `config show --with-provenance`.
	Provenance map[string]Origin
}

// Origin is where one value came from.
type Origin struct {
	Layer Layer

	// Derived marks a value computed rather than configured; no layer set it.
	Derived bool
}

// SinkAdapter names the one write path. It is compiled in, and a send: block in a served document is discarded.
const SinkAdapter = "vend"

// UploadAddressings is the closed set of addressing forms, named so a refusal can print the alternatives.
var UploadAddressings = []string{"virtual-hosted", "path-style"}

// Input is everything a resolution needs; the remote layer arrives in Layers like any other document, as LayerRemote.
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

func (e *Effective) setDerived(field string) {
	e.Provenance[field] = Origin{Derived: true}
}
