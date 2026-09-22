package transforms

import (
	"cmp"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// Span is a byte range in one decoded string value, attributed to the rule that matched it.
type Span = packs.Span

// FieldPath is a dotted path inside a record, "[]" for array elements: message.content[].text.
type FieldPath string

// Sentinel is the redaction placeholder. Nothing in it may derive from the secret (a hash prefix
// is reversible redaction); the rule id makes the ledger queryable.
func Sentinel(ruleID string) string {
	return sentinelPrefix + ":" + ruleID + "__"
}

// The ":" after it is not an entropy candidate byte, so only the prefix fuses with adjacent text;
// the entropy matcher must skip it, or a re-scrub eats the previous pass's ledger.
const sentinelPrefix = "__REDACTED"

// ExemptionSet holds identifier fields and opaque payloads the heuristics skip. Paths match exactly,
// not by key name, since additions here weaken scrubbing.
type ExemptionSet struct {
	byFamily map[string]map[FieldPath]bool
	global   map[FieldPath]bool
}

// NewExemptionSet builds the set from structural_exempt, keyed by source family or "*" for all.
func NewExemptionSet(spec map[string][]string) *ExemptionSet {
	e := &ExemptionSet{
		byFamily: map[string]map[FieldPath]bool{},
		global:   map[FieldPath]bool{},
	}
	for family, paths := range spec {
		if family == "*" {
			for _, p := range paths {
				e.global[FieldPath(p)] = true
			}
			continue
		}
		if e.byFamily[family] == nil {
			e.byFamily[family] = map[FieldPath]bool{}
		}
		for _, p := range paths {
			e.byFamily[family][FieldPath(p)] = true
		}
	}
	return e
}

// Exempt reports whether heuristics skip a field. No nil-receiver tolerance: that would fail open.
func (e *ExemptionSet) Exempt(family string, field FieldPath) bool {
	if e.global[field] {
		return true
	}
	return e.byFamily[family][field]
}

type prioritizedSpan struct {
	Span
	// 0 is a pattern rule, 1 a heuristic; lower wins.
	priority int
}

// resolveSpans merges overlaps into one placeholder attributed to the HIGHEST-CONFIDENCE rule: the
// entropy backstop fires on nearly every provider key, so any other tie-break empties the ledger.
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
		if a.priority != b.priority {
			return cmp.Compare(a.priority, b.priority)
		}
		if a.End != b.End {
			return cmp.Compare(b.End, a.End)
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})

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
			continue
		}
		resolved = append(resolved, s.Span)
		hits[s.RuleID]++
		redacted += s.End - s.Start
		cursor = s.End
	}
	return resolved, redacted, hits
}

// dropOverlappedHeuristics widens a pattern span over any heuristic reaching past it, so one secret
// yields one placeholder.
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
