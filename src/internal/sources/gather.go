package sources

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
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

	// Oldest first: for a source with a known reaper these are the ones closest to deletion.
	slices.SortFunc(matched, func(a, b Candidate) int {
		return cmp.Or(a.MTime.Compare(b.MTime), strings.Compare(a.RelPath, b.RelPath))
	})
	d.Candidates = matched
	d.Health = formats.Collected
	// Sampled, not single-file: the source is condemned only if EVERY sample fails, since one bad file is the per-file path's problem.
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
