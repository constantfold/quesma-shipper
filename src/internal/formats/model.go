// Package formats holds the vocabulary every layer shares: these words appear in the heartbeat
// document and the audit log, so they are wire values. The vocabulary types below depend on
// nothing but the standard library; a type belongs here only when several layers must agree on it
// and none owns it.
package formats

import (
	"errors"
	"time"
)

// ErrCredentialsRefused means the control plane or the store rejected this install's identity.
// It applies to the install rather than to one file, so the run must stop instead of retrying.
var ErrCredentialsRefused = errors.New("this install's credentials were refused")

// HealthState is a closed enum because a missing agent and a root whose globs match nothing look alike, but only one is drift.
type HealthState string

const (
	AgentAbsent            HealthState = "agent_absent"          // no root resolved: expected silence
	RootPresentNoMatch     HealthState = "root_present_no_match" // probable drift
	MatchPresentUnreadable HealthState = "match_present_unreadable"
	Collected              HealthState = "collected"
)

// SniffResult judges shape, never semantics.
type SniffResult string

const (
	SniffOK              SniffResult = "ok"
	SniffEmpty           SniffResult = "empty"
	SniffUnexpectedShape SniffResult = "unexpected_shape"
	SniffUnreadable      SniffResult = "unreadable"
)

// Decision is what the client decided about one file, in the audit log's vocabulary.
type Decision string

const (
	DecisionShipped   Decision = "shipped"
	DecisionUnchanged Decision = "unchanged" // content hash matched
	DecisionSkipped   Decision = "skipped"
	DecisionParked    Decision = "parked" // behind a backoff, matching the fingerprint's parked flag
	DecisionFailed    Decision = "failed" // nothing committed; re-run next time
)

type FileOutcome struct {
	// Fatal marks a failure about the install rather than the file; the run stops on it.
	Fatal bool
	// Derived payloads count as files but stay out of byte totals: nothing was read off disk.
	Derived bool

	SourceID   string
	NativePath string
	RelPath    string
	ObjectKey  string
	Decision   Decision
	BytesIn    int64
	BytesOut   int64
	Density    float64
	RuleHits   map[string]int
	Reason     string
}

// Progress receives each file's outcome as the run decides it; nil means silent.
type Progress func(sourceID string, done, total int, f FileOutcome)

type SourceOutcome struct {
	SourceID     string
	Family       string
	Health       HealthState
	Sniff        SniffResult
	AgentVersion string
	Reason       string
	Root         string

	// Remaining counts candidates this pass never started.
	Remaining int
	// Emitted marks files the shipper generated itself; they ship but stay out of byte totals.
	Emitted bool

	// Oversize counts files the size cap kept out; the largest shows whether it met one pathological file.
	Oversize        int
	OversizeLargest int64
	OversizeExample string
	OversizeLimit   int64

	Unreadable        int
	UnreadableExample string
	UnreadableReason  string
	Files             []FileOutcome

	// A mismatch loses that window's DB-side fields until the join is fixed; a skip does not.
	Enriched        int
	EnrichSkipped   int
	EnrichMismatch  int
	EnrichErrors    int
	EnrichNotes     []string
	EnricherID      string
	EnricherVersion int
	// EnrichInfos are commentary on objects that shipped, kept apart from EnrichNotes, which report loss.
	EnrichInfos []string
}

// FailureRecord persists failures for delivery by the next successful heartbeat.
// Crashes count until acknowledged; run failures count until success.
type FailureRecord struct {
	// A run that died without being able to say anything, detected by a journal with no "exit".
	LastCrash *LastCrash `json:"last_crash,omitempty"`
	// Oldest first, and bounded because it ships every run; consecutive heartbeats overlap.
	Recent              []FailureEvent `json:"recent_failures,omitempty"`
	ConsecutiveFailures int            `json:"consecutive_failures,omitempty"`
	// Overwritten every run: not failures, but what makes one explicable.
	Facts *RunFacts `json:"facts,omitempty"`
}

// RunFacts records the last run's resource costs and concurrency limits.
type RunFacts struct {
	GOMAXPROCS       int   `json:"gomaxprocs,omitempty"`
	MaxFilesPerRun   int   `json:"max_files_per_run,omitempty"`
	MaxInFlightBytes int64 `json:"max_in_flight_bytes,omitempty"`

	// HeapInuseBytes against SoftLimitBytes is the pressure; GCCycles rising is the earlier signal.
	SoftLimitBytes int64  `json:"soft_limit_bytes,omitempty"`
	HeapInuseBytes uint64 `json:"heap_inuse_bytes,omitempty"`
	SysBytes       uint64 `json:"sys_bytes,omitempty"`
	GCCycles       uint32 `json:"gc_cycles,omitempty"`

	SlowestScrubNanos int64 `json:"slowest_scrub_nanos,omitempty"`
	SlowestScrubBytes int64 `json:"slowest_scrub_bytes,omitempty"`
}

// Twenty is about five hours of a daemon failing every tick, and keeps the document a few KB.
const MaxRecentFailures = 20

// Failure kinds, a closed set so a reader can group without parsing prose. Counted() says which count toward the streak.
const (
	FailureTick         = "tick_failed"   // a run that failed, or returned nil having shipped nothing
	FailurePanic        = "panic"         // the stack stays on the machine
	FailureStoreCorrupt = "store_corrupt" // the run continues from an empty store
	FailureInit         = "init_failed"   // an install that cannot start is not collecting at all
	// Collection succeeded, but the install cannot replace itself, so no fix can reach it.
	FailureUpdate = "update_failed"
	// The SIGTERM drain: unlike a tick, nothing re-ships it on a host about to disappear.
	FailureShutdown = "shutdown_failed"
	// Read back from the crash journal by the next run; crashes keep their own counter in last_crash.
	FailureCrash = "crashed"
	// A tick that outlived its interval, recorded before its outcome is known; it may yet complete.
	FailureStalled = "tick_stalled"
)

// The message is username-placeholdered like every outbound diagnostic; a stack stays local.
type FailureEvent struct {
	At   string `json:"at"`
	Kind string `json:"kind"`
	// RunID tells twenty runs from one run failing twenty times; empty for a panic before any id is minted.
	RunID   string `json:"run_id,omitempty"`
	Message string `json:"message"`
}

// Not a ring buffer: this is serialized whole on every write, so the simple form is the cheap one.
func (r *FailureRecord) Append(e FailureEvent) {
	r.Recent = append(r.Recent, e)
	if n := len(r.Recent); n > MaxRecentFailures {
		r.Recent = append(r.Recent[:0], r.Recent[n-MaxRecentFailures:]...)
	}
}

// Counted reports whether ConsecutiveFailures includes this event. A panic splits on the run id:
// only the run loop has one, so a panicked tick counts and a panic in a one-shot verb does not.
func (e FailureEvent) Counted() bool {
	switch e.Kind {
	case FailureTick, FailureShutdown, FailureInit:
		return true
	case FailurePanic:
		return e.RunID != ""
	}
	return false
}

// LatestCounted is the newest event the streak includes, or nil once the bounded log evicted them.
func (r *FailureRecord) LatestCounted() *FailureEvent {
	for i := len(r.Recent) - 1; i >= 0; i-- {
		if r.Recent[i].Counted() {
			return &r.Recent[i]
		}
	}
	return nil
}

// Latest is the newest event, or nil on an install that has never failed.
func (r *FailureRecord) Latest() *FailureEvent {
	if len(r.Recent) == 0 {
		return nil
	}
	return &r.Recent[len(r.Recent)-1]
}

// LastCrash reports how the previous run died: the run id and lifecycle phase, never a path,
// since a journal line per file was 92% of everything the journal wrote.
type LastCrash struct {
	RunID       string `json:"run_id,omitempty"`
	Phase       string `json:"phase,omitempty"`
	Consecutive int    `json:"consecutive,omitempty"`
}

// Report is what one run did, for status, preview output and the heartbeat.
type Report struct {
	StartedAt time.Time
	// FinishedAt is the denominator of every rate the CLI prints; zero suppresses those lines.
	FinishedAt time.Time
	Sources    []SourceOutcome

	Shipped   int
	Unchanged int
	Skipped   int
	Parked    int
	Failed    int

	// Truncated is true when max_files_per_run cut the run short.
	Truncated bool
	// Remaining counts candidates never attempted; parked and oversize are not a speed problem and stay separate.
	Remaining int

	// MedianFileBytes is the middle shipped file's input size: a mean would follow one huge transcript.
	BytesRead       int64
	BytesSealed     int64
	MedianFileBytes int64

	// EnrichMismatch is the fleet-wide alarm total: there is no raw-row fallback.
	EnrichMismatch int
	Paused         bool
	PauseReason    string
	// StoreCorrupt says the fingerprint document was discarded and the run started from empty.
	StoreCorrupt bool
	// The worst single redaction: a pathologically backtracking pattern stalls an install without erroring.
	SlowestScrubNanos int64
	SlowestScrubBytes int64
}
