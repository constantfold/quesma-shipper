package engine

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

type wireDoc struct {
	StateSchema int               `json:"state_schema"`
	InstallID   string            `json:"install_id,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	SourceSpecs map[string]string `json:"source_specs,omitempty"`

	// A source_hash corrupted in place still parses and reads as a completed ship, which is silent
	// permanent loss: "a lost document only costs a re-ship" holds for forgetting a ship, never for
	// falsely remembering one. Absent on documents written before this field existed.
	Checksum string `json:"checksum,omitempty"`

	Entries []wireEntry `json:"entries"`
}

// Hashed with the checksum field cleared, so both sides compute over the same bytes. Marshal, never
// MarshalIndent: formatting must be free to change without invalidating every store in the fleet.
func checksumOf(doc wireDoc) (string, error) {
	doc.Checksum = ""
	body, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("state: checksum: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

type wireEntry struct {
	SourceID     string       `json:"source_id"`
	NativePath   string       `json:"native_path"`
	SourceSize   int64        `json:"source_size,omitempty"`
	SourceMTime  string       `json:"source_mtime,omitempty"`
	Attempts     int          `json:"attempts,omitempty"`
	SourceHash   string       `json:"source_hash,omitempty"`
	Enricher     *EnricherRef `json:"enricher,omitempty"`
	OutputHash   string       `json:"output_hash,omitempty"`
	Parked       bool         `json:"parked,omitempty"`
	LastError    string       `json:"last_error,omitempty"`
	BackoffUntil string       `json:"backoff_until,omitempty"`
}

// encode serializes deterministically: entries sorted by key, so equal state gives equal bytes.
func encode(installID string, updatedAt time.Time, specs map[string]string, entries map[Key]Fingerprint) ([]byte, error) {
	// json.Marshal writes map keys sorted, so source_specs is deterministic too.
	doc := wireDoc{StateSchema: StateSchema, InstallID: installID, SourceSpecs: specs, Entries: []wireEntry{}}
	if !updatedAt.IsZero() {
		doc.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	}

	keys := slices.SortedFunc(maps.Keys(entries), func(a, b Key) int {
		return cmp.Or(strings.Compare(a.SourceID, b.SourceID), strings.Compare(a.NativePath, b.NativePath))
	})

	for _, k := range keys {
		fp := entries[k]
		e := wireEntry{
			SourceID:   k.SourceID,
			NativePath: k.NativePath,
			SourceSize: fp.SourceSize,
			SourceHash: fp.SourceHash,
			OutputHash: fp.OutputHash,
			Attempts:   fp.Attempts,
			Parked:     fp.Parked,
			LastError:  fp.LastError,
			Enricher:   fp.Enricher,
		}
		if !fp.SourceMTime.IsZero() {
			// RFC3339Nano, not RFC3339: the pre-filter compares this against the file's mtime for
			// EXACT equality, so whole seconds here re-read and re-hash every file on every tick.
			// Rounding both sides instead would skip a same-second change. Do not lower the precision.
			e.SourceMTime = fp.SourceMTime.UTC().Format(time.RFC3339Nano)
		}
		if !fp.BackoffUntil.IsZero() {
			e.BackoffUntil = fp.BackoffUntil.UTC().Format(time.RFC3339)
		}
		doc.Entries = append(doc.Entries, e)
	}

	sum, err := checksumOf(doc)
	if err != nil {
		return nil, err
	}
	doc.Checksum = sum

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("state: encode: %w", err)
	}
	body = append(body, '\n')

	// Validate on the way out: a state file that fails its own schema is a bug to catch here.
	if err := formats.ValidateRaw(formats.FingerprintState, body, "state: document"); err != nil {
		return nil, err
	}
	return body, nil
}

func load(stateDir string, maxBytes int64) (Document, error) {
	path := filepath.Join(stateDir, FileName)
	raw, _, err := platform.ReadWhole(path, maxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First run. An empty store is not an error: everything is simply unshipped.
			return Document{Entries: map[Key]Fingerprint{}}, nil
		}
		return Document{}, fmt.Errorf("state: read %s: %w", path, err)
	}

	// Verify the value checksum here; encode already validates the schema. Missing fields default to a safe re-ship; negative attempts are invalid.
	var doc wireDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("state: parse %s: %w", path, err)
	}
	// The only schema guard on the load path: rejecting costs one re-upload, guessing costs more.
	if doc.StateSchema != StateSchema {
		return Document{}, fmt.Errorf("%w: document says %d, this client speaks %d",
			ErrSchemaMismatch, doc.StateSchema, StateSchema)
	}
	// Absent means written before the field existed; it earns one on the next rewrite. A wrong one
	// fails the whole load, because a partly-trusted store is the failure this catches.
	if doc.Checksum != "" {
		want, err := checksumOf(doc)
		if err != nil {
			return Document{}, err
		}
		if want != doc.Checksum {
			return Document{}, fmt.Errorf("state: %s failed its checksum", path)
		}
	}

	out := Document{
		InstallID:   doc.InstallID,
		SourceSpecs: doc.SourceSpecs,
		Entries:     make(map[Key]Fingerprint, len(doc.Entries)),
	}
	if out.SourceSpecs == nil {
		out.SourceSpecs = map[string]string{}
	}
	if doc.UpdatedAt != "" {
		out.UpdatedAt, _ = time.Parse(time.RFC3339, doc.UpdatedAt)
	}
	for _, e := range doc.Entries {
		if e.Attempts < 0 {
			return Document{}, fmt.Errorf("state: entry %s %s: negative attempts %d",
				e.SourceID, e.NativePath, e.Attempts)
		}
		fp := Fingerprint{
			SourceSize: e.SourceSize,
			SourceHash: e.SourceHash,
			OutputHash: e.OutputHash,
			Attempts:   e.Attempts,
			Parked:     e.Parked,
			LastError:  e.LastError,
			Enricher:   e.Enricher,
		}
		if e.SourceMTime != "" {
			fp.SourceMTime, _ = time.Parse(time.RFC3339, e.SourceMTime)
		}
		if e.BackoffUntil != "" {
			fp.BackoffUntil, _ = time.Parse(time.RFC3339, e.BackoffUntil)
		}
		out.Entries[Key{
			SourceID:   e.SourceID,
			NativePath: e.NativePath,
		}] = fp
	}
	return out, nil
}
