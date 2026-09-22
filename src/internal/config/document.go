// Package config merges configuration layers and records provenance.
// Local authority controls widening; compiled path denials and root checks still apply.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// AcceptedConfigVersions is enumerated, never a range: an unknown config_version is a hard error.
var AcceptedConfigVersions = []int{1}

// Document is one config layer's contents. Every field is a pointer or a slice so absent stays distinguishable from zero.
type Document struct {
	// IssuedAt and Org are the served envelope, so only the remote layer may carry them.
	IssuedAt *string `yaml:"issued_at"`
	Org      *string `yaml:"org"`

	ConfigVersion *int             `yaml:"config_version"`
	Mode          *Mode            `yaml:"mode"`
	Sources       []SourceOverride `yaml:"sources"`

	// Read and discarded so an older config.yaml with these blocks still parses.
	Sink        map[string]any `yaml:"send"`
	CrashReport map[string]any `yaml:"crash_report"`

	Scrub          *Scrub              `yaml:"scrub"`
	Encryption     *Encryption         `yaml:"encryption"`
	MaxFilesPerRun *int                `yaml:"max_files_per_run"`
	DrainDeadline  *string             `yaml:"drain_deadline"`
	StateDir       *string             `yaml:"state_dir"`
	UploadTargets  []UploadTarget      `yaml:"upload_targets"`
	StructuralEx   map[string][]string `yaml:"structural_exempt"`
	Autoupdate     *Autoupdate         `yaml:"autoupdate"`

	// TelemetryEndpoint is a path such as `/v1/telemetry`, never a URL: it resolves against the enrolled
	// control-plane origin, so a served document cannot redirect telemetry. Absent means disabled.
	TelemetryEndpoint *string `yaml:"telemetry_endpoint"`
}

// Autoupdate: off is free from any layer, re-enabling is not.
type Autoupdate struct {
	Enabled *bool `yaml:"enabled"`
}

type Mode struct {
	Schedule *string `yaml:"schedule"` // a Go duration such as "15m"
}

// SourceOverride adjusts a compiled source. It cannot create one: an id absent from the catalog is refused.
type SourceOverride struct {
	ID           string   `yaml:"id"`
	Enabled      *bool    `yaml:"enabled"`
	Roots        []string `yaml:"roots"`
	Include      []string `yaml:"include"`
	Exclude      []string `yaml:"exclude"`
	MaxFileBytes *int64   `yaml:"max_file_bytes"`

	// Enrichers toggles a registered enricher; config can never attach one, that would be config installing code.
	Enrichers map[string]bool `yaml:"enrichers"`
}

// UploadTarget declares one destination for a presigned upload ticket. Machine-owner only.
type UploadTarget struct {
	Origin            string `yaml:"origin"`      // scheme://host[:port], no wildcards
	Addressing        string `yaml:"addressing"`  // "virtual-hosted" or "path-style"
	PathPrefix        string `yaml:"path_prefix"` // empty, or "/bucket" for path-style
	AllowLoopbackHTTP bool   `yaml:"allow_loopback_http"`
}

// Scrub lists only grow across layers: additions make scrubbing stricter.
type Scrub struct {
	RulePacks      []string `yaml:"rule_packs"`
	SecretKeyNames []string `yaml:"secret_key_names"`
}

// Encryption is who can read what this install ships: age keys beside the install's own, unioned across layers.
type Encryption struct {
	AdditionalRecipients    []string `yaml:"additional_recipients"`
	IncludeInstallRecipient *bool    `yaml:"include_install_recipient"` // absent means true
}

// ParseDocument decodes the machine owner's own file. Unknown fields are refused: a typo must not be a silent no-op.
func ParseDocument(raw []byte) (*Document, error) {
	return parseDocument(raw, true)
}

// ParseServedDocument decodes the org's served document, ignoring unknown fields.
func ParseServedDocument(raw []byte) (*Document, error) {
	return parseDocument(raw, false)
}

func parseDocument(raw []byte, knownFields bool) (*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(knownFields)
	var d Document
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, io.EOF) {
			return &Document{}, nil // an empty layer, not a broken one
		}
		return nil, fmt.Errorf("config: parse document: %w", err)
	}
	return &d, nil
}

type LayeredDocument struct {
	Layer Layer
	Doc   *Document
}
