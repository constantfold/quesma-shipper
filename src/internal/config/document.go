// Package config merges configuration layers and records provenance.
// Local authority controls widening; compiled path denials and root checks still apply.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
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

	// TelemetryEndpoint is a path resolved against the enrolled origin, never a URL, so it cannot redirect telemetry; absent is off.
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

const (
	DefaultTick = 15 * time.Minute // the design's loss-window bound
	MinTick     = time.Minute      // a poll loop at seconds is a hot loop
)

// TickInterval turns `mode.schedule` into the tick interval; a bad value is refused with a warning and the default, never approximated.
func TickInterval(schedule string) (time.Duration, string) {
	s := strings.TrimSpace(schedule)
	if s == "" {
		return DefaultTick, ""
	}
	d, err := time.ParseDuration(s)
	var problem string
	switch {
	case err != nil:
		problem = `not a duration like "5m"`
	case d <= 0:
		problem = "a tick interval must be positive"
	case d < MinTick:
		return MinTick, fmt.Sprintf("mode.schedule %q is under the %s floor — ticking every %s", schedule, MinTick, MinTick)
	default:
		return d, ""
	}
	return DefaultTick, fmt.Sprintf("mode.schedule %q: %s — ticking every %s instead", schedule, problem, DefaultTick)
}

// maxConfigBytes bounds a config file; anything larger is a mistake or an attempt to exhaust memory.
const maxConfigBytes = 1 << 20

// Paths locates the one config file and the state directory; the remote layer needs enrollment instead.
type Paths struct {
	User     string
	StateDir string
}

// DefaultPaths honours XDG where it applies.
func DefaultPaths(home string, lookup func(string) (string, bool)) Paths {
	xdg := func(name string, fallback ...string) string {
		if v, ok := lookup(name); ok && v != "" {
			return v
		}
		return filepath.Join(append([]string{home}, fallback...)...)
	}
	return Paths{
		User:     filepath.Join(xdg("XDG_CONFIG_HOME", ".config"), "trajectory-shipper", "config.yaml"),
		StateDir: filepath.Join(xdg("XDG_STATE_HOME", ".local", "state"), "trajectory-shipper"),
	}
}

// LoadLayers reads the user's config file: missing is clone-and-run, unreadable is an error, since skipping it drops the layer.
func LoadLayers(p Paths) ([]LayeredDocument, error) {
	raw, _, err := platform.ReadWhole(p.User, maxConfigBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case errors.Is(err, platform.ErrNotRegular):
		return nil, fmt.Errorf("config: %s is not a regular file", p.User)
	case err != nil:
		return nil, fmt.Errorf("config: cannot read %s: %w", p.User, err)
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", p.User, err)
	}
	return []LayeredDocument{{Layer: LayerUser, Doc: doc}}, nil
}

func UserConfigFound(p Paths) (string, bool) {
	_, err := os.Stat(p.User)
	return p.User, err == nil
}
