// Heartbeat construction. Discovery health is NOT upload tracking: per source, no cursor offsets,
// no object keys, no statement about what was uploaded. It answers "is this source still
// findable", and it needs nothing configured, so it carries while any backend is unreachable.
package engine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// Name is the heartbeat object's name under the install's state prefix.
const Name = "heartbeat.json"

// Heartbeat is the whole document: every field is about the collector, none about a payload.
type Heartbeat struct {
	HeartbeatVersion int    `json:"heartbeat_version"`
	At               string `json:"at"`

	OrganizationID string `json:"organization_id"`
	InstallID      string `json:"install_id"`

	ClientVersion string `json:"client_version"`
	ConfigVersion int    `json:"config_version"`

	// ConfigExpired says collection continued under a cached config past its expiry.
	ConfigExpired bool   `json:"config_expired,omitempty"`
	RunID         string `json:"run_id,omitempty"`

	// Embedded, so last_crash stays top-level; the newest event may describe this run.
	formats.FailureRecord

	Sources []SourceHealth `json:"sources"`
}

// SourceHealth is one source's discovery state.
type SourceHealth struct {
	SourceID string `json:"source_id"`
	Family   string `json:"family,omitempty"`

	// State distinguishes agent_absent from root_present_no_match: expected silence versus drift.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`

	Sniff        string `json:"shape_sniff,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`

	// Volume, not content.
	FilesSeen  int `json:"files_seen"`
	Shipped    int `json:"shipped"`
	Unchanged  int `json:"unchanged"`
	Parked     int `json:"parked"`
	Failed     int `json:"failed"`
	Oversize   int `json:"oversize,omitempty"`
	Unreadable int `json:"unreadable,omitempty"`

	// EnrichMismatch is a top-level alarm: the derived view is the only carrier of the DB-side fields.
	Enriched       int    `json:"enriched,omitempty"`
	EnrichSkipped  int    `json:"enrich_skipped,omitempty"`
	EnrichMismatch int    `json:"enrich_mismatch,omitempty"`
	EnrichErrors   int    `json:"enrich_errors,omitempty"`
	Enricher       string `json:"enricher,omitempty"`

	// RedactionDensity is the mean across this source's files; a fleet-wide spike means rule drift.
	RedactionDensity float64 `json:"redaction_density,omitempty"`

	LastCollectedAt string `json:"last_collected_at,omitempty"`
}

// WithReport fills the heartbeat's discovery facts while retaining its install metadata.
func (hb Heartbeat) WithReport(rep formats.Report, now time.Time) Heartbeat {
	hb.HeartbeatVersion = 1
	hb.At = now.UTC().Format(time.RFC3339)
	hb.Sources = []SourceHealth{}

	for _, s := range rep.Sources {
		sh := SourceHealth{
			SourceID:     s.SourceID,
			Family:       s.Family,
			State:        string(s.Health),
			Reason:       s.Reason,
			Sniff:        string(s.Sniff),
			AgentVersion: s.AgentVersion,
			FilesSeen:    len(s.Files),
			Oversize:     s.Oversize,
			Unreadable:   s.Unreadable,

			Enriched:       s.Enriched,
			EnrichSkipped:  s.EnrichSkipped,
			EnrichMismatch: s.EnrichMismatch,
			EnrichErrors:   s.EnrichErrors,
		}
		if s.EnricherID != "" {
			sh.Enricher = fmt.Sprintf("%s@%d", s.EnricherID, s.EnricherVersion)
		}

		var densitySum float64
		var densityCount int
		for _, f := range s.Files {
			switch f.Decision {
			case "shipped":
				sh.Shipped++
			case "unchanged":
				sh.Unchanged++
			case "parked":
				sh.Parked++
			case "failed":
				sh.Failed++
			}
			if f.Density > 0 {
				densitySum += f.Density
				densityCount++
			}
		}
		if densityCount > 0 {
			sh.RedactionDensity = densitySum / float64(densityCount)
		}
		if sh.Shipped > 0 {
			sh.LastCollectedAt = hb.At
		}
		hb.Sources = append(hb.Sources, sh)
	}
	return hb
}

// Encode serializes the heartbeat.
func (h Heartbeat) Encode() ([]byte, error) {
	body, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("health: encode heartbeat: %w", err)
	}
	return append(body, '\n'), nil
}
