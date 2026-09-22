package sources

import (
	"context"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// HealthState is the per-source discovery verdict, aliased so gather and the heartbeat document agree on one set of strings.
type HealthState = formats.HealthState

const (
	AgentAbsent            = formats.AgentAbsent
	RootPresentNoMatch     = formats.RootPresentNoMatch
	MatchPresentUnreadable = formats.MatchPresentUnreadable
	Collected              = formats.Collected
)

type SniffResult = formats.SniffResult

const (
	SniffOK              = formats.SniffOK
	SniffEmpty           = formats.SniffEmpty
	SniffUnexpectedShape = formats.SniffUnexpectedShape
	SniffUnreadable      = formats.SniffUnreadable
)

// Candidate is one discovered file or generated payload.
type Candidate struct {
	// Path is absolute for files, or a stable name for generated content.
	Path string
	// RelPath is relative to the resolved root and derives the mirror key, so a store that moves keeps its keys.
	RelPath string
	Load    func(context.Context) (Payload, error)
	Size    int64
	MTime   time.Time
}

type Payload struct {
	Bytes   []byte
	MTime   time.Time
	Warning string
}

func fileLoader(path string, maxBytes int64) func(context.Context) (Payload, error) {
	return func(ctx context.Context) (Payload, error) {
		if err := ctx.Err(); err != nil {
			return Payload{}, err
		}
		raw, info, err := platform.ReadWhole(path, maxBytes)
		if err != nil {
			return Payload{}, err
		}
		return Payload{Bytes: raw, MTime: info.ModTime()}, nil
	}
}

// Discovery is what one source's discovery pass found, plus why.
type Discovery struct {
	Health HealthState
	// Reason explains a non-collected health state, for doctor and the heartbeat.
	Reason string
	// Deferred means inspection skipped a check that requires collection.
	Deferred bool
	// Ignored says the ignore list dropped something, so a source emptied by it is not mistaken for drift.
	Ignored bool

	// Oversize and Unreadable are reported even on a healthy source: what they name never ships.
	Oversize          []Oversize
	Unreadable        int
	UnreadableExample string
	UnreadableReason  string

	// Sniff lands verbatim in manifests, heartbeats and doctor output; SniffFailures condemns the
	// source only when every sample failed.
	Sniff         SniffResult
	SniffFailures int
	// AgentVersion is read from the store, making a parse-failure spike attributable to an agent release.
	AgentVersion string

	// Candidates are oldest-first: for a source with a reaper, the files closest to deletion.
	Candidates []Candidate
}

// Request is everything a discovery pass is given; each primitive uses a different slice of it.
type Request struct {
	Source Resolved
	// All is every resolved source, for a primitive whose input is another source's files.
	All []Resolved
	// Deny and Ignore are install-wide; a nil Ignore drops nothing.
	Deny   *List
	Ignore *RepoFilter
	// StateDir is the ONLY place a primitive may write its derived artifacts, never inside an agent's store.
	StateDir string
	// Username feeds the path placeholder, so an inventory record carries a pseudonymised path.
	Username string
	Now      func() time.Time
	Interval time.Duration
	Context  context.Context
	Env      Env
	Capture  bool
}

// Oversize is one file the size cap kept out of a run.
type Oversize struct {
	RelPath     string
	Size, Limit int64
}
