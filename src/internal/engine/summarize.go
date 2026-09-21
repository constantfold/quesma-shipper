package engine

import (
	"slices"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// summarize totals bytes from the outcomes rather than accumulating: derived.go appends outcomes
// without passing through the fold. Emitted and derived are excluded so an idle run totals zero.
func summarize(rep *Report) {
	var shippedIn []int64
	for _, s := range rep.Sources {
		if s.Emitted {
			continue
		}
		for _, f := range s.Files {
			if f.Derived {
				continue
			}
			rep.BytesRead += f.BytesIn
			rep.BytesSealed += f.BytesOut
			if f.Decision == formats.DecisionShipped {
				shippedIn = append(shippedIn, f.BytesIn)
			}
		}
	}
	rep.MedianFileBytes = median(shippedIn)
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	sorted := slices.Clone(v)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}
