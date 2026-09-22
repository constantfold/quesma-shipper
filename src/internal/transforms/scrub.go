// The scrubber removes secrets and PII before packaging, and fails CLOSED: an engine error means
// the file does not upload. Detectors favour recall; they match the DECODED value and replace
// exactly the matching source span.
package transforms

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// Hint is advisory: a payload that does not parse falls back to raw-text scanning either way.
type Hint struct {
	// Family selects structural exemptions.
	Family string
	JSONL  bool
}

// ScanMode values record how a payload was actually handled, for the manifest.
const (
	ScanModeDecodedJSON = "decoded_json_values"
	ScanModeRawText     = "raw_text"
	ScanModeMixed       = "mixed"
)

// Result is the scrubbed payload plus the ledger.
type Result struct {
	Out           []byte
	BytesRedacted int
	BytesTotal    int
	RuleHits      map[string]int
	ScanMode      string

	// A torn tail is expected (it ships byte-exact and the next flush supersedes it), so it counts here, not as an error.
	LinesParsed     int
	LinesRawScanned int
}

// Density is bytes redacted over bytes total, so downstream can drop shredded objects and a jump names the rule at fault.
func (r Result) Density() float64 {
	if r.BytesTotal == 0 {
		return 0
	}
	return float64(r.BytesRedacted) / float64(r.BytesTotal)
}

func (r *Result) record(n int, hits map[string]int) {
	r.BytesRedacted += n
	for id, c := range hits {
		r.RuleHits[id] += c
	}
}

// Config builds a Scrubber.
type Config struct {
	RulePacks      []string
	Exemptions     map[string][]string
	Username       string
	SecretKeyNames []string
	Entropy        EntropyConfig
}

// DefaultConfig is the compiled baseline.
func DefaultConfig() Config {
	return Config{
		RulePacks:      []string{packs.GitleaksCore, packs.QuesmaExtra, packs.CloudKeys, packs.GenericEntropy, packs.PIICore},
		Exemptions:     CompiledExemptions(),
		Username:       "",
		SecretKeyNames: DefaultSecretKeyNames(),
		Entropy:        DefaultEntropyConfig(),
	}
}

// A constant, not a setting: a tunable floor invites tuning it too low for a speculative decode.
const base64MinLength = 32

// Scrubber is a compiled, reusable redaction engine.
type Scrubber struct {
	patterns []gatedPattern

	// The only heuristic, nil when not configured; it mistakes structure for secrets, so exemptions are checked before it.
	entropy *entropyMatcher

	// Not a detector, so the path-user rewrite runs on exempt fields too.
	pathUser string

	keyNames *keyNameMatcher
	exempt   *ExemptionSet

	// Read-only once built, so a Scrubber stays safe to share.
	prefilter *packs.Prefilter

	// A backtracking pattern can stall for seconds without erroring; nothing else reports it.
	slowestNanos atomic.Int64
	slowestBytes atomic.Int64
}

// Slowest reports the worst Scrub so far with its payload size, since a large file is legitimately slow.
func (s *Scrubber) Slowest() (time.Duration, int64) {
	return time.Duration(s.slowestNanos.Load()), s.slowestBytes.Load()
}

// noteCost does not retry the size store: a lost race costs one sample of a worst-case hint.
func (s *Scrubber) noteCost(d time.Duration, size int) {
	n := int64(d)
	for {
		prev := s.slowestNanos.Load()
		if n <= prev {
			return
		}
		if s.slowestNanos.CompareAndSwap(prev, n) {
			s.slowestBytes.Store(int64(size))
			return
		}
	}
}

// gatedMatcher runs only when the shared keyword automaton fired for it. It takes no field path on
// purpose, so exemptions cannot reach it and pattern matchers provably scan exempt fields too.
type gatedMatcher interface {
	MatchScannedIn(value string, scan *packs.ValueScan) []Span
}

type gatedPattern struct {
	m    gatedMatcher
	gate packs.Gate
}

// New compiles a Scrubber. An unknown pack is an error, so fewer rules than configured never run.
func New(cfg Config) (*Scrubber, error) {
	s := &Scrubber{exempt: NewExemptionSet(cfg.Exemptions)}
	// Rejected, not clamped: the scanner would read a negative floor as "every run".
	if cfg.Entropy.MinLength < 0 {
		return nil, fmt.Errorf("scrub: entropy min_length %d is negative", cfg.Entropy.MinLength)
	}

	prefilter := packs.NewPrefilterBuilder()

	for _, name := range cfg.RulePacks {
		switch name {
		case packs.GenericEntropy:
			s.entropy = newEntropyMatcher(cfg.Entropy, cfg.Username)
		default:
			rules, err := packs.Load(name)
			if err != nil {
				return nil, err
			}
			for _, r := range rules {
				gate, err := prefilter.AddKeywords(r.Keywords())
				if err != nil {
					return nil, fmt.Errorf("scrub: pack %s rule %s: %w", name, r.RuleID(), err)
				}
				s.patterns = append(s.patterns, gatedPattern{m: r, gate: gate})
			}
		}
	}

	s.keyNames = newKeyNameMatcher(cfg.SecretKeyNames)
	// nil stems always match, so a non-ASCII configured name is still redacted, just not prefiltered.
	keyGate, err := prefilter.AddKeywords(s.keyNames.stems)
	if err != nil {
		return nil, fmt.Errorf("scrub: secret key names: %w", err)
	}
	s.patterns = append(s.patterns, gatedPattern{m: s.keyNames, gate: keyGate})
	s.prefilter = prefilter.Build()

	s.pathUser = cfg.Username
	return s, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Scrub redacts a payload; errors fail closed. A line that does not parse is raw-text scanned, not
// an error, which lets a torn tail still ship.
func (s *Scrubber) Scrub(payload []byte, hint Hint) (Result, error) {
	started := time.Now()
	defer func() { s.noteCost(time.Since(started), len(payload)) }()
	res := Result{
		RuleHits:   map[string]int{},
		BytesTotal: len(payload),
		ScanMode:   ScanModeDecodedJSON,
	}
	// One Scrubber serves many goroutines, so no per-value state may live on it.
	var scan packs.ValueScan
	if !hint.JSONL {
		res.Out = []byte(s.scrubRawText(string(payload), &res, &scan))
		res.ScanMode = ScanModeRawText
		res.LinesRawScanned = 1
		return res, nil
	}

	var walker jsonWalker
	// Copy on first change: a file with no secret ships the input slice itself.
	var out []byte

	for rest := payload; len(rest) > 0; {
		lineStart := len(payload) - len(rest)
		ensureOutput := func() {
			if out == nil {
				out = make([]byte, 0, len(payload))
				out = append(out, payload[:lineStart]...)
			}
		}
		var body, ending []byte
		body, ending, rest = nextLine(rest)
		if len(bytes.TrimSpace(body)) == 0 {
			if out != nil {
				out = append(out, body...)
				out = append(out, ending...)
			}
			continue
		}

		walker.reset(s, hint.Family, &scan, body)
		walkErr := walker.walkLine()
		if walkErr == nil {
			res.LinesParsed++
			res.record(walker.redacted, walker.hits)
			if len(walker.edits) > 0 {
				ensureOutput()
				var err error
				out, err = walker.appendTo(out, body)
				if err != nil {
					return Result{}, fmt.Errorf("scrub engine: apply JSON redaction spans: %w", err)
				}
			} else if out != nil {
				out = append(out, body...)
			}
		} else {
			res.LinesRawScanned++
			text := string(body)
			scrubbed := s.scrubRawText(text, &res, &scan)
			if scrubbed != text {
				ensureOutput()
				out = append(out, scrubbed...)
			} else if out != nil {
				out = append(out, body...)
			}
		}
		if out != nil {
			out = append(out, ending...)
		}
	}

	switch {
	case res.LinesRawScanned > 0 && res.LinesParsed > 0:
		res.ScanMode = ScanModeMixed
	case res.LinesRawScanned > 0:
		res.ScanMode = ScanModeRawText
	}
	if out == nil {
		res.Out = payload
	} else {
		res.Out = out
	}
	return res, nil
}

// scrubRawText skips heuristics: with no field path there is no exemption, and the entropy
// backstop would shred any hex digest or base64 blob in a terminal capture.
func (s *Scrubber) scrubRawText(text string, res *Result, scan *packs.ValueScan) string {
	plan := s.planValueWith(text, nil, "", "", scan)
	res.record(plan.redacted, plan.hits)
	return plan.apply(text)
}

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

// planValue plans one decoded JSON string; the walker maps the spans back to the original token.
func (s *Scrubber) planValue(value, key string, field FieldPath, family string, scan *packs.ValueScan) valuePlan {
	entropy := s.entropy
	if s.exempt.Exempt(family, field) {
		// Exemptions turn off the heuristics and nothing else.
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

	seen := s.prefilter.Scan(value)
	// The shared pass for keyword-less rules; lazy until one asks.
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

	// One level of base64, bounding work; the whole value goes, since re-encoding rewrites bytes.
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

// pathUserReplacementSpans matches against the detector-rewritten value without building it: a
// neighbouring sentinel supplies the boundary byte, and a swallowed occurrence no longer exists.
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
	// The same answer as all four decoders failing, without their buffers.
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

// base64Shaped is deliberately permissive: only rejection must be sound, as the real decoder follows.
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
