// Enrichers join staged raw data with declared stores before redaction.
// Outputs are deterministic and versioned; failures never prevent raw files from shipping.
package transforms

import (
	"crypto/sha256"
	"encoding/hex"
)

// Status is the outcome of one enrichment. Anything but StatusOK means that window's DB-side
// fields are lost until a release fixes the join, so these are health alarms.
type Status string

const (
	StatusOK       Status = "ok"       // the derived object is complete
	StatusSkipped  Status = "skipped"  // nothing to derive; not an alarm
	StatusMismatch Status = "mismatch" // THE alarm: the join rules are vendor behaviour and drift
	StatusError    Status = "error"    // the read or the computation failed
)

// RawUnit is one staged raw file an enricher may read: staged CONTENT, not a path to re-open,
// so derived_from attests to the bytes that shipped and enrichers get no filesystem access.
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
	// Becomes the mirror key; by convention <input path>.enriched.jsonl, beside its input.
	NativePath string

	Payload     []byte   // pre-redaction, taking the same path as a raw file
	DerivedFrom []string // the source hash of every raw input
	OutputHash  string   // the object re-ships only when this changes

	Status     Status
	Mismatches int // non-zero only without an object: a mismatch aborts the derived entry

	// Shortfalls shipped native-only inside a StatusOK object, counted so a conversation with holes
	// is not byte-identical to a complete one: explained store gaps, events the evidence could not
	// decide, and mid-file transcript lines that did not decode (an alarm).
	Repeats          int
	Tail             int
	Ambiguous        int
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
	Objects    []Derived // empty is a normal outcome

	// Inputs that produced nothing, split because only Mismatched is an alarm.
	Skipped    int
	Mismatched int
	Errors     int

	// Notes are alarms explaining data that did not ship, Infos notes about objects that did.
	// Never payload bytes or redacted values: diagnostics must not become a side channel.
	Notes []string
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

	// Agent database locations in preference order, with catalog-root ~ and $VAR syntax. Compiled
	// in, never configured: an arbitrary SQLite path is one the catalog never approved.
	DBCandidates() []string

	// A unit-free enricher runs on EVERY flush: its input is the agent's store, which moves on
	// its own schedule, so an idle install would otherwise never report.
	NeedsUnits() bool

	// Enrich returns a result, never an error: no enricher failure should stop a flush.
	Enrich(Input) EnrichResult
}

// Registry is the compiled set, keyed by Enricher.ID. Config can only enable or disable entries.
type Registry map[string]Enricher

// NewRegistry builds the compiled registry.
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
