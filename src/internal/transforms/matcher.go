package transforms

import (
	"cmp"
	"slices"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// Span is a rule-attributed byte range shared with the pattern matchers.
type Span = packs.Span

// FieldPath is a dotted path to a value inside a record, with "[]" standing for array
// elements: content[].image.hex, message.content[].text, toolUseResult.stdout.
type FieldPath string

// Sentinel identifies the rule, never the secret: even a secret's hash can reveal it.
func Sentinel(ruleID string) string {
	return sentinelPrefix + ":" + ruleID + "__"
}

// sentinelPrefix is the run-visible head of every sentinel: the ":" after it is outside the
// entropy candidate alphabet, so only this part fuses with adjacent text. The entropy matcher
// must keep skipping candidates carrying it, or a re-scrub eats the previous pass's ledger.
const sentinelPrefix = "__REDACTED"

// ExemptionSet protects identifier and opaque fields from heuristics; paths match exactly.
type ExemptionSet struct {
	byFamily map[string]map[FieldPath]bool
}

// NewExemptionSet accepts paths keyed by source family, or "*" for all families.
func NewExemptionSet(spec map[string][]string) *ExemptionSet {
	e := &ExemptionSet{byFamily: map[string]map[FieldPath]bool{}}
	for family, paths := range spec {
		e.byFamily[family] = map[FieldPath]bool{}
		for _, p := range paths {
			e.byFamily[family][FieldPath(p)] = true
		}
	}
	return e
}

// Exempt checks heuristic exemptions; a nil set is a programming error, never a fail-open default.
func (e *ExemptionSet) Exempt(family string, field FieldPath) bool {
	return e.byFamily["*"][field] || e.byFamily[family][field]
}

// prioritizedSpan carries the matcher class alongside the span, so overlapping
// matches resolve by confidence rather than alphabetically.
type prioritizedSpan struct {
	Span
	// priority 0 is a high-confidence pattern rule, 1 is a heuristic. Lower wins.
	priority int
}

// resolveSpans merges overlaps into one placeholder attributed to the highest-confidence rule.
func resolveSpans(value string, patternSpans, heuristicSpans []Span) ([]Span, int, map[string]int) {
	if len(patternSpans) == 0 && len(heuristicSpans) == 0 {
		return nil, 0, nil
	}

	spans := make([]prioritizedSpan, 0, len(patternSpans)+len(heuristicSpans))
	for _, s := range patternSpans {
		spans = append(spans, prioritizedSpan{Span: s, priority: 0})
	}
	for _, s := range heuristicSpans {
		spans = append(spans, prioritizedSpan{Span: s, priority: 1})
	}

	slices.SortFunc(spans, func(a, b prioritizedSpan) int {
		if a.Start != b.Start {
			return cmp.Compare(a.Start, b.Start)
		}
		return cmp.Or(
			cmp.Compare(a.priority, b.priority),
			cmp.Compare(b.End, a.End),
			cmp.Compare(a.RuleID, b.RuleID),
		)
	})

	// Keeping both would nest placeholders or split one secret across two.
	spans = dropOverlappedHeuristics(spans)

	resolved := make([]Span, 0, len(spans))
	hits := map[string]int{}
	redacted := 0
	cursor := 0

	for _, s := range spans {
		if s.Start < 0 || s.End > len(value) || s.Start >= s.End {
			continue
		}
		if s.Start < cursor {
			// Already inside a replaced region.
			continue
		}
		resolved = append(resolved, s.Span)
		hits[s.RuleID]++
		redacted += s.End - s.Start
		cursor = s.End
	}
	return resolved, redacted, hits
}

// dropOverlappedHeuristics removes heuristic spans intersecting a pattern span and widens
// that span over any reach past it, so one secret yields one confidently attributed
// placeholder.
func dropOverlappedHeuristics(spans []prioritizedSpan) []prioritizedSpan {
	var patterns []prioritizedSpan
	for _, s := range spans {
		if s.priority == 0 {
			patterns = append(patterns, s)
		}
	}

	out := make([]prioritizedSpan, 0, len(spans))
	for _, s := range spans {
		if s.priority == 0 {
			out = append(out, s)
			continue
		}
		overlapped := false
		for i, p := range patterns {
			if s.Start < p.End && p.Start < s.End {
				// Extend the confident span so no tail of the secret escapes.
				if s.End > patterns[i].End {
					patterns[i].End = s.End
					for j := range out {
						if out[j].priority == 0 && out[j].Start == p.Start && out[j].RuleID == p.RuleID {
							out[j].End = s.End
						}
					}
				}
				overlapped = true
				break
			}
		}
		if !overlapped {
			out = append(out, s)
		}
	}
	return out
}
