// Enrichers join staged raw data with declared stores before redaction.
// Outputs are deterministic and versioned; failures never prevent raw files from shipping.
package transforms

import (
	"crypto/sha256"
	"encoding/hex"
)

// Status is one enrichment's outcome; anything but StatusOK loses DB-side fields, so these are alarms.
type Status string

const (
	StatusOK       Status = "ok"       // the derived object is complete
	StatusSkipped  Status = "skipped"  // nothing to derive; not an alarm
	StatusMismatch Status = "mismatch" // THE alarm: the join rules are vendor behaviour and drift
	StatusError    Status = "error"    // the read or the computation failed
)

// RawUnit is staged CONTENT, not a path, so derived_from attests to shipped bytes and enrichers get no filesystem.
type RawUnit struct {
	NativePath string // names the derived object and is the join key
	Content    []byte // raw pre-redaction bytes, as staged
	SourceHash string // becomes an entry in derived_from
}

// Input is what an enricher gets.
type Input struct {
	Units      []RawUnit // this source's staged raw units in this flush
	DBPath     string    // the declared agent database; empty means absent, not an error
	ScratchDir string    // where the read ladder may put a snapshot: never beside the source
}

// Derived is one derived object.
type Derived struct {
	NativePath string // the mirror key: by convention <input path>.enriched.jsonl

	Payload     []byte   // pre-redaction, taking the same path as a raw file
	DerivedFrom []string // the source hash of every raw input
	OutputHash  string   // the object re-ships only when this changes

	Status     Status
	Mismatches int // non-zero only without an object: a mismatch aborts the derived entry

	// Native-only shortfalls inside a StatusOK object, counted so one with holes differs from a complete one.
	Repeats, Tail, Ambiguous, LineDecodeErrors int

	// Read provenance: the rows never ship, so this is the only account of their origin.
	DBReadMethod string
	DBKeyspaces  []string
	DBRowsRead   int
}

// EnrichResult is one enricher's whole contribution to a flush.
type EnrichResult struct {
	EnricherID string
	Version    int
	Objects    []Derived // empty is a normal outcome

	Skipped, Mismatched, Errors int // inputs that produced nothing; only Mismatched is an alarm

	// Notes explain data that did not ship, Infos objects that did; never payload bytes (no side channel).
	Notes, Infos []string
}

// Enricher is a compiled per-source hook.
type Enricher interface {
	// Identify the code that produced an output, so derived objects are supersedable.
	ID() string
	Version() int

	// The DECLARED read scope, fixed at registration so a hook cannot widen it at runtime.
	Table() string
	Keyspaces() []string

	// Compiled-in agent database locations in preference order, with catalog-root ~ and $VAR syntax.
	DBCandidates() []string

	// A unit-free enricher runs on EVERY flush, since the store moves while an install sits idle.
	NeedsUnits() bool

	// Enrich returns a result, never an error: no enricher failure should stop a flush.
	Enrich(Input) EnrichResult
}

// Registry is the compiled set, keyed by Enricher.ID. Config can only enable or disable entries.
type Registry map[string]Enricher

func NewRegistry(es ...Enricher) Registry {
	r := Registry{}
	for _, e := range es {
		r[e.ID()] = e
	}
	return r
}

// Hash is the output-hash helper every enricher uses, so the change signal is computed one way.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
