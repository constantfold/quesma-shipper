package transforms

import (
	"cmp"
	"encoding/base64"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// base64MinLength is the floor below which a speculative decode is not worth it.
const base64MinLength = 32

type replacementSpan struct {
	Start, End  int
	Replacement string
}

type valuePlan struct {
	spans    []replacementSpan
	redacted int
	hits     map[string]int
}

func (p valuePlan) apply(value string) string {
	if len(p.spans) == 0 {
		return value
	}
	var b strings.Builder
	b.Grow(len(value) + 64)
	cursor := 0
	for _, span := range p.spans {
		b.WriteString(value[cursor:span.Start])
		b.WriteString(span.Replacement)
		cursor = span.End
	}
	b.WriteString(value[cursor:])
	return b.String()
}

// planValue plans one decoded JSON string; an exempt field stands down the heuristics and nothing else.
func (s *Scrubber) planValue(value, key, field, family string, scan *packs.ValueScan) valuePlan {
	entropy := s.entropy
	if s.exempt["*"][field] || s.exempt[family][field] {
		entropy = nil
	}
	return s.planValueWith(value, entropy, key, scan)
}

func (s *Scrubber) planValueWith(value string, entropy *entropyMatcher, key string, scan *packs.ValueScan) valuePlan {
	// A key that names a secret takes the whole value, whatever shape the value has.
	if key != "" && s.keyNames.MatchesKeyName(key) && value != "" {
		return wholeValuePlan(value, "key-name")
	}

	// A keyword set that did not fire means the matcher behind it cannot match.
	seen := s.prefilter.Scan(value)
	scan.Reset(value)

	var patternSpans, heuristicSpans []Span
	for _, p := range s.patterns {
		if seen.Has(p.gate) {
			patternSpans = append(patternSpans, p.m.MatchScannedIn(value, scan)...)
		}
	}
	if entropy != nil {
		heuristicSpans = entropy.Match(value)
	}

	// One level of base64 keeps work bounded; the whole value goes, as a re-encoding would rewrite bytes.
	if len(patternSpans) == 0 && len(heuristicSpans) == 0 && len(value) >= base64MinLength {
		if id, hit := s.base64Hit(value, scan); hit {
			return wholeValuePlan(value, id)
		}
	}

	resolved, redacted, hits := resolveSpans(value, patternSpans, heuristicSpans)
	plan := valuePlan{redacted: redacted, hits: hits}
	for _, span := range resolved {
		plan.spans = append(plan.spans, replacementSpan{Start: span.Start, End: span.End, Replacement: Sentinel(span.RuleID)})
	}

	// Runs last and unconditionally, including on values already redacted.
	if pathSpans, n := pathUserReplacementSpans(value, s.pathUser, plan.spans); n > 0 {
		plan.spans = append(plan.spans, pathSpans...)
		slices.SortFunc(plan.spans, func(a, b replacementSpan) int { return cmp.Compare(a.Start, b.Start) })
		plan.redacted += n
		if plan.hits == nil {
			plan.hits = map[string]int{}
		}
		plan.hits["path-user"]++
	}
	return plan
}

func wholeValuePlan(value, ruleID string) valuePlan {
	return valuePlan{
		spans:    []replacementSpan{{Start: 0, End: len(value), Replacement: Sentinel(ruleID)}},
		redacted: len(value),
		hits:     map[string]int{ruleID: 1},
	}
}

// pathUserReplacementSpans finds the username as if in the rewritten value: sentinels bound it, and swallow it.
func pathUserReplacementSpans(value, username string, blocked []replacementSpan) ([]replacementSpan, int) {
	if len(username) < 2 || value == "" || !strings.Contains(value, username) {
		return nil, 0
	}
	var spans []replacementSpan
	redacted := 0
	blockedAt := 0
	for from := 0; from+len(username) <= len(value); {
		rel := strings.Index(value[from:], username)
		if rel < 0 {
			break
		}
		start := from + rel
		end := start + len(username)
		for blockedAt < len(blocked) && blocked[blockedAt].End <= start {
			blockedAt++
		}
		if blockedAt < len(blocked) && blocked[blockedAt].Start < end {
			from = end
			continue
		}

		leftOK := start == 0 || !isAlnumByte(value[start-1])
		if blockedAt > 0 && blocked[blockedAt-1].End == start {
			r := blocked[blockedAt-1].Replacement
			leftOK = !isAlnumByte(r[len(r)-1])
		}
		rightOK := end == len(value) || !isAlnumByte(value[end])
		if blockedAt < len(blocked) && blocked[blockedAt].Start == end {
			rightOK = !isAlnumByte(blocked[blockedAt].Replacement[0])
		}
		if leftOK && rightOK {
			spans = append(spans, replacementSpan{Start: start, End: end, Replacement: formats.UserPlaceholder})
			redacted += len(username)
		}
		from = end
	}
	return spans, redacted
}

// base64Hit decodes one level and reports the first pattern rule that fires inside.
func (s *Scrubber) base64Hit(value string, scan *packs.ValueScan) (string, bool) {
	trimmed := strings.TrimSpace(value)
	// The same answer as four failing decoders, without their buffers.
	if !base64Shaped(trimmed) {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(trimmed)
		if err != nil || len(decoded) == 0 {
			continue
		}
		text := string(decoded)
		seen := s.prefilter.Scan(text)
		// Reusing the caller's scratch is safe: this answer ends the ladder for the value.
		scan.Reset(text)
		for _, p := range s.patterns {
			if !seen.Has(p.gate) {
				continue
			}
			if found := p.m.MatchScannedIn(text, scan); len(found) > 0 {
				return found[0].RuleID, true
			}
		}
		return "", false
	}
	return "", false
}

// base64Shaped covers both alphabets, padding and the skipped carriage return; only rejection must be sound.
func base64Shaped(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnumByte(c):
		case c == '+', c == '/', c == '=', c == '-', c == '_', c == '\r':
		default:
			return false
		}
	}
	return true
}

// Span is a rule-attributed byte range shared with the pattern matchers.
type Span = packs.Span

// Sentinel identifies the rule, never the secret: even a secret's hash can reveal it.
func Sentinel(ruleID string) string {
	return sentinelPrefix + ":" + ruleID + "__"
}

// sentinelPrefix is the sentinel part inside the entropy alphabet, skipped so a re-scrub keeps the ledger.
const sentinelPrefix = "__REDACTED"

// prioritizedSpan resolves overlaps by confidence: 0 is a pattern rule, 1 a heuristic.
type prioritizedSpan struct {
	Span
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
		return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(b.End, a.End), cmp.Compare(a.RuleID, b.RuleID))
	})

	// Keeping both would nest placeholders or split one secret across two.
	spans = dropOverlappedHeuristics(spans)

	resolved := make([]Span, 0, len(spans))
	hits := map[string]int{}
	redacted := 0
	cursor := 0

	for _, s := range spans {
		if s.Start < cursor || s.Start < 0 || s.End > len(value) || s.Start >= s.End {
			continue
		}
		resolved = append(resolved, s.Span)
		hits[s.RuleID]++
		redacted += s.End - s.Start
		cursor = s.End
	}
	return resolved, redacted, hits
}

// dropOverlappedHeuristics drops heuristics intersecting a pattern span, widening it over their reach.
func dropOverlappedHeuristics(spans []prioritizedSpan) []prioritizedSpan {
	patterns := slices.DeleteFunc(slices.Clone(spans), func(s prioritizedSpan) bool { return s.priority != 0 })
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
