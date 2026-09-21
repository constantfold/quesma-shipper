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

	Load func(context.Context) (Payload, error)

	Size  int64
	MTime time.Time
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

	// Deferred means inspection skipped a check that requires collection.
	Deferred bool

	// SniffFailures counts sampled files that were unreadable or the wrong shape; it is a source-wide verdict only when every sample failed.
	SniffFailures int

	// Oversize lists files the size cap excluded. Reported even on a healthy source: they never ship and the store's reaper deletes them.
	Oversize []Oversize

	// Unreadable counts what the walk could not look at. Reported even on a healthy source: a skipped subtree never ships again.
	Unreadable int

	// UnreadableExample is the first path that failed, and UnreadableReason its error.
	UnreadableExample string
	UnreadableReason  string

	// Sniff is the shape verdict for the sampled candidates. It lands verbatim in manifests, heartbeats and doctor output.
	Sniff SniffResult

	// AgentVersion is read from the store itself, making a downstream parse-failure spike attributable to an agent release.
	AgentVersion string

	// Candidates are oldest-first: for a source with a reaper, the files closest to deletion cannot be collected later.
	Candidates []Candidate

	// Reason explains a non-collected health state, for doctor and the heartbeat.
	Reason string

	// Ignored says the ignore list dropped something, so a source emptied by it is not
	// mistaken for drift. A bool: nothing reports on an ignored repository.
	Ignored bool
}

// Request is everything a discovery pass is given; each primitive uses a different slice of it.
type Request struct {
	Source Resolved

	// All is every resolved source, for a primitive whose input is another source's files.
	All []Resolved

	// Deny is install-wide: the compiled list plus served additions, not something a source configures.
	Deny *List

	// Ignore drops candidates of an ignored repository. Install-wide like Deny; nil
	// means nothing is ignored.
	Ignore *RepoFilter

	// StateDir is the ONLY place a primitive may write its derived artifacts, never inside an agent's store.
	StateDir string

	// Username feeds the path placeholder, so an inventory record carries a pseudonymised path.
	Username string

	Now      func() time.Time
	Interval time.Duration

	Context context.Context
	Env     Env
	Capture bool
}

// Oversize is one file the size cap kept out of a run.
type Oversize struct {
	RelPath string
	Size    int64
	Limit   int64
}
