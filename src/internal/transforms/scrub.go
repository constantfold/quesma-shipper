package transforms

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// Hint is advisory: a payload that does not parse falls back to raw-text scanning either way.
type Hint struct {
	Family string // the source family, which selects structural exemptions
	JSONL  bool   // one JSON value per line; anything else is scanned as raw text
}

// ScanMode records how a payload was actually handled, for the manifest.
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
}

// Density is recorded per object so downstream can drop shredded objects and spot a haywire rule.
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
		SecretKeyNames: DefaultSecretKeyNames(),
		Entropy:        DefaultEntropyConfig(),
	}
}

// Scrubber is a compiled, reusable redaction engine, safe to share between goroutines.
type Scrubber struct {
	patterns []gatedPattern

	// nil when generic-entropy is not configured; it mistakes structure for secrets, so exemptions apply first.
	entropy *entropyMatcher

	// A rewriter, not a detector, so it runs on exempt fields too; empty disables it.
	pathUser string

	keyNames  *keyNameMatcher
	prefilter *packs.Prefilter

	// Source family ("*" for all) to exact field paths the heuristics skip, as in content[].image.hex.
	exempt map[string]map[string]bool

	// A pathological input can make a pattern backtrack for seconds without erroring.
	slowestNanos atomic.Int64
	slowestBytes atomic.Int64
}

// Slowest reports the worst Scrub so far with its payload size: a large file is legitimately slow.
func (s *Scrubber) Slowest() (time.Duration, int64) {
	return time.Duration(s.slowestNanos.Load()), s.slowestBytes.Load()
}

// noteCost retries a lost race until this sample wins or a slower sample has already won.
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

// gatedMatcher takes no field path: structural exemptions must never suppress pattern matches.
type gatedMatcher interface {
	MatchScannedIn(value string, scan *packs.ValueScan) []Span
}

type gatedPattern struct {
	m    gatedMatcher
	gate packs.Gate
}

// New compiles a Scrubber. A configured pack with no corpus is an error, never fewer rules.
func New(cfg Config) (*Scrubber, error) {
	// Rejected rather than clamped: the scanner would read a negative floor as "every run".
	if cfg.Entropy.MinLength < 0 {
		return nil, fmt.Errorf("scrub: entropy min_length %d is negative", cfg.Entropy.MinLength)
	}
	s := &Scrubber{
		exempt:   map[string]map[string]bool{},
		keyNames: newKeyNameMatcher(cfg.SecretKeyNames),
		pathUser: cfg.Username,
	}
	for family, paths := range cfg.Exemptions {
		s.exempt[family] = map[string]bool{}
		for _, p := range paths {
			s.exempt[family][p] = true
		}
	}

	prefilter := packs.NewPrefilterBuilder()
	for _, name := range cfg.RulePacks {
		if name == packs.GenericEntropy {
			s.entropy = newEntropyMatcher(cfg.Entropy, cfg.Username)
			continue
		}
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

	// nil stems yield AlwaysGate, so a non-ASCII configured name is still redacted, just not prefiltered.
	keyGate, err := prefilter.AddKeywords(s.keyNames.stems)
	if err != nil {
		return nil, fmt.Errorf("scrub: secret key names: %w", err)
	}
	s.patterns = append(s.patterns, gatedPattern{m: s.keyNames, gate: keyGate})
	s.prefilter = prefilter.Build()
	return s, nil
}

// Scrub redacts a payload; errors fail closed, and a line that does not parse is raw-text scanned.
func (s *Scrubber) Scrub(payload []byte, hint Hint) (Result, error) {
	started := time.Now()
	defer func() { s.noteCost(time.Since(started), len(payload)) }()
	res := Result{RuleHits: map[string]int{}, BytesTotal: len(payload), ScanMode: ScanModeDecodedJSON}
	// Per-call scratch: one Scrubber serves many goroutines.
	var scan packs.ValueScan
	if !hint.JSONL {
		res.Out = []byte(s.scrubRawText(string(payload), &res, &scan))
		res.ScanMode = ScanModeRawText
		return res, nil
	}

	var walker jsonWalker
	parsedLines, rawLines := 0, 0
	// Copy on first change: a file with no secret ships the input slice itself.
	var out []byte
	for rest := payload; len(rest) > 0; {
		lineStart := len(payload) - len(rest)
		var body, ending []byte
		body, ending, rest = nextLine(rest)

		var scrubbed string
		parsed, dirty := false, false
		if len(bytes.TrimSpace(body)) > 0 {
			walker.reset(s, hint.Family, &scan, body)
			if walker.walkLine() == nil {
				parsed = true
				parsedLines++
				res.record(walker.redacted, walker.hits)
				dirty = len(walker.edits) > 0
			} else {
				// Syntax errors, torn tails and over-deep records belong to the raw scanner.
				rawLines++
				scrubbed = s.scrubRawText(string(body), &res, &scan)
				dirty = scrubbed != string(body)
			}
		}

		if dirty && out == nil {
			out = append(make([]byte, 0, len(payload)), payload[:lineStart]...)
		}
		switch {
		case out == nil:
			continue
		case dirty && parsed:
			var err error
			if out, err = walker.appendTo(out, body); err != nil {
				return Result{}, fmt.Errorf("scrub engine: apply JSON redaction spans: %w", err)
			}
		case dirty:
			out = append(out, scrubbed...)
		default:
			out = append(out, body...)
		}
		out = append(out, ending...)
	}

	switch {
	case rawLines > 0 && parsedLines > 0:
		res.ScanMode = ScanModeMixed
	case rawLines > 0:
		res.ScanMode = ScanModeRawText
	}
	res.Out = payload
	if out != nil {
		res.Out = out
	}
	return res, nil
}

// scrubRawText applies patterns and path rewrites without heuristics: raw text has no field exemptions.
func (s *Scrubber) scrubRawText(text string, res *Result, scan *packs.ValueScan) string {
	plan := s.planValueWith(text, nil, "", scan)
	res.record(plan.redacted, plan.hits)
	return plan.apply(text)
}
