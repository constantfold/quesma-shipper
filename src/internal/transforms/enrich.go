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
	StatusOK      Status = "ok"      // the derived object is complete
	StatusSkipped Status = "skipped" // nothing to derive; not an alarm
	// The join did not line up. THE alarm: the alignment rules are undocumented vendor
	// behaviour, and a drifted join silently loses the fields it carries.
	StatusMismatch Status = "mismatch"
	StatusError    Status = "error" // the read or the computation failed
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

	Status Status

	// Non-zero with StatusOK is impossible by contract: a mismatch aborts the derived entry.
	Mismatches int

	// Store shortfalls the join explains, shipped native-only inside a StatusOK object, one
	// counter per class so a conversation with holes is not byte-identical to a complete one.
	Repeats int
	Tail    int

	// Events the evidence could not decide, where the join attached nothing rather than guess.
	Ambiguous int

	// Transcript lines before the tail that did not decode: an alarm, since their blocks never
	// reached the join while the object still ships.
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

	// Objects are the derived objects to ship. Empty is a normal outcome.
	Objects []Derived

	// Inputs that produced nothing, split because only Mismatched is an alarm.
	Skipped    int
	Mismatched int
	Errors     int

	// Alarms for the audit log and `doctor`, each explaining data that did not ship. Never
	// payload bytes or redacted values: diagnostics must not become a side channel.
	Notes []string

	// Informational notes about objects that DID ship, apart so no reader re-parses note text.
	Infos []string
}

// Enricher is a compiled per-source hook.
type Enricher interface {
	// Identify the code that produced an output, so derived objects are supersedable.
	ID() string
	Version() int

	// The DECLARED read scope, fixed at registration: a hook that could widen its own scope
	// at runtime would make the compiled ceiling meaningless.
	Table() string
	Keyspaces() []string

	// Per-platform locations of the agent database in preference order, same ~ and $VAR
	// syntax as catalog roots. Compiled in, never configured: an arbitrary SQLite path is
	// one the catalog never approved. nil when the enricher has no database.
	DBCandidates() []string

	// A unit-free enricher runs on EVERY flush, because its input is the agent's store, which
	// moves on its own schedule: otherwise an idle install never reports its account at all.
	NeedsUnits() bool

	// Enrich returns a result rather than an error for anything short of a programming fault:
	// no enricher failure should stop a flush.
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
