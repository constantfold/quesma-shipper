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
	ConfigVersion  int
	OrganizationID string // the organization= key segment; standalone installs write "default"
	ConfigExpired  bool   // the remote layer in force is a cached one past expiry, which cannot widen scope
	Schedule       string
	DrainDeadline  time.Duration // bounds `run --once --drain` and the SIGTERM drain
	StateDir       string
	MaxFilesPerRun int
	Sources        []ResolvedSource
	Catalog        *sources.Compiled // the catalog the sources were resolved from, so no verb parses it twice
	UploadTargets  []UploadTarget    // the origins a presigned ticket may name; empty means unpinned

	RulePacks      []string
	SecretKeyNames []string
	StructuralEx   map[string][]string
	Deny           *sources.List

	AdditionalRecipients    []string
	IncludeInstallRecipient bool
	AutoupdateEnabled       bool   // a released build may replace itself at daemon startup
	TelemetryEndpoint       string // the control-plane path telemetry goes to; empty means off

	// Provenance attributes every value to the layer that set it, for `config --with-provenance`.
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
	Catalog       *sources.Compiled
	Layers        []LayeredDocument
	ConfigExpired bool // set by the caller when the remote layer is a stale cache; Resolve has no clock
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

func (e *Effective) reject(field, format string, args ...any) error {
	return &RejectionError{e.Provenance[field].Layer, field, fmt.Sprintf(format, args...)}
}

func (e *Effective) setOrigin(field string, l Layer) {
	e.Provenance[field] = Origin{Layer: l}
}
