package transforms

import (
	"cmp"
	"encoding/base64"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// base64MinLength is the floor below which a speculative decode is not worth it. A
// constant, not a setting: a setting that reads as tunable invites tuning it below the floor.
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

// planValue applies the full ladder to one decoded JSON string without building the
// rewritten value; the walker maps the decoded spans back to the original token.
func (s *Scrubber) planValue(value, key string, field FieldPath, family string, scan *packs.ValueScan) valuePlan {
	entropy := s.entropy
	if s.exempt.Exempt(family, field) {
		// Detector-scoped: the field stands down the heuristics and nothing else.
		entropy = nil
	}
	return s.planValueWith(value, entropy, key, field, scan)
}

func (s *Scrubber) planValueWith(
	value string,
	entropy *entropyMatcher,
	key string,
	field FieldPath,
	scan *packs.ValueScan,
) valuePlan {
	// A key that names a secret takes the whole value, whatever shape the value has.
	if key != "" && s.keyNames.MatchesKeyName(key) && value != "" {
		return valuePlan{
			spans:    []replacementSpan{{Start: 0, End: len(value), Replacement: Sentinel("key-name")}},
			redacted: len(value),
			hits:     map[string]int{"key-name": 1},
		}
	}

	// A gate that did not fire means the matcher behind it cannot match.
	seen := s.prefilter.Scan(value)
	// The shared pass for rules with no keyword to gate on; lazy until one asks.
	scan.Reset(value)

	var patternSpans, heuristicSpans []Span
	for _, p := range s.patterns {
		if !seen.Has(p.gate) {
			continue
		}
		patternSpans = append(patternSpans, p.m.MatchScannedIn(value, scan)...)
	}
	if entropy != nil {
		heuristicSpans = entropy.Match(value)
	}

	// One level of base64, never recursion: work stays bounded per byte. The whole
	// encoded value goes rather than a patched re-encoding, which would rewrite bytes
	// the shipper is supposed to preserve.
	if len(patternSpans) == 0 && len(heuristicSpans) == 0 && len(value) >= base64MinLength {
		if id, hit := s.base64Hit(value, scan); hit {
			return valuePlan{
				spans:    []replacementSpan{{Start: 0, End: len(value), Replacement: Sentinel(id)}},
				redacted: len(value),
				hits:     map[string]int{id: 1},
			}
		}
	}

	resolved, redacted, hits := resolveSpans(value, patternSpans, heuristicSpans)
	plan := valuePlan{redacted: redacted, hits: hits}
	for _, span := range resolved {
		plan.spans = append(plan.spans, replacementSpan{
			Start: span.Start, End: span.End, Replacement: Sentinel(span.RuleID),
		})
	}

	// Runs last and unconditionally, including on values already redacted.
	if s.pathUser != "" {
		pathSpans, n := pathUserReplacementSpans(value, s.pathUser, plan.spans)
		if n > 0 {
			plan.spans = append(plan.spans, pathSpans...)
			slices.SortFunc(plan.spans, func(a, b replacementSpan) int {
				return cmp.Compare(a.Start, b.Start)
			})
			plan.redacted += n
			if plan.hits == nil {
				plan.hits = map[string]int{}
			}
			plan.hits["path-user"]++
		}
	}
	return plan
}

// pathUserReplacementSpans finds username occurrences in the detector-rewritten value
// without constructing it: a detector touching a neighbour contributes the sentinel's
// boundary byte, and an occurrence a detector swallowed no longer exists.
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
			spans = append(spans, replacementSpan{
				Start: start, End: end, Replacement: formats.UserPlaceholder,
			})
			redacted += len(username)
		}
		from = end
	}
	return spans, redacted
}

// base64Hit decodes one level and reports the first pattern rule that fires inside.
func (s *Scrubber) base64Hit(value string, scan *packs.ValueScan) (string, bool) {
	trimmed := strings.TrimSpace(value)
	// A byte outside every base64 alphabet means all four decoders would fail, so this
	// is the same answer without their buffers.
	if !base64Shaped(trimmed) {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(trimmed)
		if err != nil || len(decoded) == 0 {
			continue
		}
		text := string(decoded)
		seen := s.prefilter.Scan(text)
		// Safe to reuse the caller's scratch: this answer short-circuits the rest of
		// the ladder for the value.
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

// base64Shaped covers the standard and URL alphabets, padding, and the carriage return
// the decoders skip. Deliberately permissive: only the rejection has to be sound, since
// what passes still goes through the real decoder.
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
