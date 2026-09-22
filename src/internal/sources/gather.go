package sources

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Discover dispatches only to collectors compiled into this build.
func Discover(req Request) (Discovery, error) {
	switch req.Source.Gather {
	case "file_glob", "compressed_file":
		return discoverByGlob(req)
	case "sidecar":
		return discoverSidecar(req)
	case "account":
		return (&accounts{}).discover(req)
	default:
		return Discovery{}, fmt.Errorf("gather: no compiled primitive %q", req.Source.Gather)
	}
}

func discoverByGlob(req Request) (Discovery, error) {
	src := req.Source
	d := Discovery{Health: formats.AgentAbsent}
	if src.Root == "" {
		d.Reason = cmp.Or(src.RootUnresolvedReason, "no candidate root resolved")
		return d, nil
	}

	matched, oversize, bad, ignored := walkGlobs(src, req.Deny, req.Ignore)
	d.Oversize, d.Ignored = oversize, ignored
	d.Unreadable, d.UnreadableExample = bad.count, bad.example
	d.UnreadableReason = bad.reason()
	if len(matched) == 0 {
		// Root present, globs matched nothing: probable drift, and never to be confused with agent_absent.
		d.Health = formats.RootPresentNoMatch
		d.Reason = fmt.Sprintf("root %s exists but no file matched %v", src.Root, src.Include)
		switch {
		case bad.count > 0:
			d.Health = formats.MatchPresentUnreadable
			d.Reason = bad.reason()
		case d.Ignored:
			d.Reason = ignoredReason
		case len(oversize) > 0:
			// Every match was over the cap: saying "no file matched" would send the reader to their globs instead.
			d.Health = formats.MatchPresentUnreadable
			d.Reason = fmt.Sprintf("%d file(s) matched but every one is over the %d-byte cap",
				len(oversize), src.MaxFileBytes)
		}
		return d, nil
	}

	slices.SortFunc(matched, func(a, b Candidate) int {
		return cmp.Or(a.MTime.Compare(b.MTime), strings.Compare(a.RelPath, b.RelPath))
	})
	d.Candidates = matched
	d.Health = formats.Collected
	d.Sniff, d.AgentVersion, d.SniffFailures = sniffSample(matched, src.Sniff)
	if d.Sniff == formats.SniffUnreadable || d.Sniff == formats.SniffUnexpectedShape {
		// Found but unusable: a store that switched substrate lands here rather than shipping garbage.
		d.Health = formats.MatchPresentUnreadable
		d.Reason = fmt.Sprintf("shape sniff failed on every one of %d sampled files; last was %s",
			d.SniffFailures, d.Sniff)
		d.Candidates = nil
	}
	return d, nil
}

// ignoredReason explains a source emptied by the ignore list: the config working, not drift.
const ignoredReason = "every file this source found belongs to a repository you are not tracking"

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
	Health formats.HealthState
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

	// Sniff lands verbatim in manifests, heartbeats and doctor; the source is condemned only when every sample failed.
	Sniff         formats.SniffResult
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
