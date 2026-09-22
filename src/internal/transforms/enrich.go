// Enrichers are compiled per-source hooks that join staged raw units with a higher-fidelity store
// (Cursor's SQLite) BEFORE redaction; they are the only capture path for those fields. Raw files ship
// regardless, so enrichment fails open; output is deterministic so its hash is a change signal.
package transforms

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Status is one enrichment's outcome; anything but StatusOK means DB-side fields are missing.
type Status string

const (
	StatusOK Status = "ok" // the derived object is complete

	// StatusSkipped means there was nothing to derive; not an alarm.
	StatusSkipped Status = "skipped"

	// StatusMismatch is THE alarm: the join rules are undocumented vendor behaviour that drifts.
	StatusMismatch Status = "mismatch"

	StatusError Status = "error" // the read or the computation failed
)

// RawUnit is staged CONTENT, not a path, so derived_from attests to the shipped bytes and
// enrichers get no filesystem access.
type RawUnit struct {
	NativePath string
	Content    []byte
	SourceHash string
}

// Input is what an enricher gets.
type Input struct {
	Units []RawUnit

	// DBPath is empty when the database is absent, which is not an error.
	DBPath string

	// ScratchDir is where the read ladder may put a snapshot: never beside the source.
	ScratchDir string
}

// Derived is one derived object.
type Derived struct {
	// The mirror key, by convention <input path>.enriched.jsonl so it lists beside its input.
	NativePath string

	// Payload is pre-redaction and takes the same path as a raw file.
	Payload     []byte
	DerivedFrom []string

	// OutputHash is the change signal: the object re-ships only when it changes.
	OutputHash string

	Status Status

	// Non-zero with StatusOK is impossible by contract: a mismatch aborts the derived entry.
	Mismatches int

	// Explained store shortfalls shipped native-only, so an object with holes differs from a complete one.
	Repeats int
	Tail    int

	// Events the join left bare rather than guess: undecided holes, not explained ones.
	Ambiguous int

	// Undecodable lines before the tail: an alarm, since their enrichment is lost while the object ships.
	LineDecodeErrors int

	// Read provenance: the rows never ship, so this is the only account of their origin.
	DBReadMethod string
	DBKeyspaces  []string
	DBRowsRead   int
}

// EnrichResult is one enricher's whole contribution to a flush.
type EnrichResult struct {
	EnricherID string
	Version    int

	// Empty is a normal outcome.
	Objects []Derived

	// Inputs that produced nothing, split because only Mismatched is an alarm.
	Skipped    int
	Mismatched int
	Errors     int

	// Alarms explaining data that did not ship; never payload bytes, so diagnostics are no side channel.
	Notes []string

	// Notes about objects that DID ship, kept apart so reporting never parses text to detect loss.
	Infos []string
}

// Enricher is a compiled per-source hook.
type Enricher interface {
	// Identify the code that produced an output, so derived objects are supersedable.
	ID() string
	Version() int

	// The DECLARED read scope, fixed at registration so a hook cannot widen it at runtime.
	Table() string
	Keyspaces() []string

	// Compiled-in DB locations in preference order (catalog ~ and $VAR syntax), never configured; nil if none.
	DBCandidates() []string

	// A unit-free enricher runs on EVERY flush, or an idle logged-in install never reports its account.
	NeedsUnits() bool

	// Enrich returns a result, not an error: no enricher failure should stop a flush.
	Enrich(Input) EnrichResult
}

// Registry is the compiled set; config can enable or disable entries but never add one.
type Registry struct {
	byID map[string]Enricher
}

// NewRegistry builds the compiled registry.
func NewRegistry(es ...Enricher) *Registry {
	r := &Registry{byID: map[string]Enricher{}}
	for _, e := range es {
		r.byID[e.ID()] = e
	}
	return r
}

// For returns a registered enricher.
func (r *Registry) For(id string) (Enricher, error) {
	e, ok := r.byID[id]
	if !ok {
		// Refused, never ignored: otherwise the DB-side fields are lost with no signal.
		return nil, fmt.Errorf("enrich: no enricher %q in this build", id)
	}
	return e, nil
}

// Hash is the output-hash helper every enricher uses, so the change signal is computed one way.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
