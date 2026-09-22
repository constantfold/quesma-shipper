package transforms

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// ManifestVersion is the wire-contract version; downstream rejects an unknown one outright.
const ManifestVersion = 1

// Manifest is the first tar entry of every mirror object and the only wire copy of the native path.
// manifest.schema.json is the authority, validated on seal and on open so the two cannot drift.
type Manifest struct {
	ManifestVersion int `json:"manifest_version"`

	OrganizationID string `json:"organization_id"`
	InstallID      string `json:"install_id"`

	SourceID      string `json:"source_id"`
	SourceFamily  string `json:"source_family,omitempty"`
	NativePath    string `json:"native_path"`
	Gather        string `json:"gather"`
	ArtifactClass string `json:"artifact_class"`

	// SourceHash covers raw pre-redaction bytes, ShippedHash the archived ones; redaction changes bytes.
	SourceHash  string `json:"source_hash"`
	ShippedHash string `json:"shipped_hash"`

	PayloadSize  int64      `json:"payload_size"`
	PayloadMTime *time.Time `json:"payload_mtime,omitempty"`

	AgentVersion string `json:"agent_version,omitempty"`
	ShapeSniff   string `json:"shape_sniff,omitempty"`

	Redaction *RedactionSummary `json:"redaction,omitempty"`

	Encryption *Encryption `json:"encryption,omitempty"`

	Client        Client `json:"client"`
	ConfigVersion int    `json:"config_version,omitempty"`
	ConfigExpired bool   `json:"config_expired,omitempty"`
	SealedAt      string `json:"sealed_at"`

	// RunID joins the object to the sealing process's crash journal, audit entries and heartbeat.
	RunID string `json:"run_id,omitempty"`

	Derived          bool          `json:"derived,omitempty"`
	Enricher         *EnricherRef  `json:"enricher,omitempty"`
	DerivedFrom      []string      `json:"derived_from,omitempty"`
	EnrichStatus     string        `json:"enrich_status,omitempty"`
	EnrichMismatches int           `json:"enrich_mismatches,omitempty"`
	DBProvenance     *DBProvenance `json:"db_provenance,omitempty"`

	// What an ok object could not enrich; only line decode errors are loss (torn final line excluded).
	EnrichRepeats          int `json:"enrich_repeats,omitempty"`
	EnrichTail             int `json:"enrich_tail,omitempty"`
	EnrichAmbiguous        int `json:"enrich_ambiguous,omitempty"`
	EnrichLineDecodeErrors int `json:"enrich_line_decode_errors,omitempty"`
}

// RedactionSummary holds counts per rule, never byte ranges, which would fingerprint each secret.
type RedactionSummary struct {
	Density  float64        `json:"density"`
	RuleHits map[string]int `json:"rule_hits,omitempty"`
	ScanMode string         `json:"scan_mode,omitempty"`
}

// Encryption records the recipients an object was encrypted to: public key IDs only.
type Encryption struct {
	Scheme          string   `json:"scheme"`
	RecipientKeyIDs []string `json:"recipient_key_ids"`
}

// Client identifies the sealing build as separate facts, so grouping is a comparison, not a
// substring match. All optional but Version: an unstamped build has no truthful Commit.
type Client struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

type EnricherRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// DBProvenance records what an enricher read; the rows never ship, so this is their only account.
type DBProvenance struct {
	DBPath     string   `json:"db_path,omitempty"`
	ReadMethod string   `json:"read_method,omitempty"`
	Keyspaces  []string `json:"keyspaces,omitempty"`
	RowsRead   int      `json:"rows_read,omitempty"`
}

// Encode validates against the schema, so a manifest downstream would reject never reaches a bucket.
func (m Manifest) Encode() ([]byte, error) {
	if m.ManifestVersion == 0 {
		m.ManifestVersion = ManifestVersion
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("seal: encode manifest: %w", err)
	}
	if err := validateManifestBytes(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// DecodeManifest parses and validates a manifest.
func DecodeManifest(raw []byte) (Manifest, error) {
	if err := validateManifestBytes(raw); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("seal: decode manifest: %w", err)
	}
	if m.ManifestVersion != ManifestVersion {
		return Manifest{}, fmt.Errorf("seal: manifest_version %d, this client speaks %d",
			m.ManifestVersion, ManifestVersion)
	}
	return m, nil
}

func validateManifestBytes(raw []byte) error {
	err := formats.ValidateRaw(formats.Manifest, raw)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, formats.ErrNotJSON):
		return fmt.Errorf("seal: manifest is %w", err)
	}
	return fmt.Errorf("seal: manifest does not satisfy its schema: %w", err)
}

// ObjectMetadata is the plaintext PUT metadata, so a consumer can dedupe with a HEAD. The native
// path is deliberately absent: it travels only inside the age ciphertext.
func (m Manifest) ObjectMetadata() map[string]string {
	md := map[string]string{
		"manifest-version": fmt.Sprint(m.ManifestVersion),
		"source-id":        m.SourceID,
		"source-hash":      m.SourceHash,
		"shipped-hash":     m.ShippedHash,
		"artifact-class":   m.ArtifactClass,
	}
	if m.AgentVersion != "" {
		md["agent-version"] = m.AgentVersion
	}
	if m.ShapeSniff != "" {
		md["shape-sniff"] = m.ShapeSniff
	}
	if m.Derived {
		md["derived"] = "true"
	}
	if m.EnrichStatus != "" {
		md["enrich-status"] = m.EnrichStatus
	}
	return md
}
