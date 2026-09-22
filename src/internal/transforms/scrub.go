package transforms

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// Hint is advisory: a payload that does not parse falls back to raw-text scanning
// either way.
type Hint struct {
	// Family is the source family, used to select structural exemptions.
	Family string

	// JSONL means one JSON value per line; anything else is scanned as raw text.
	JSONL bool
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

	// A torn tail is expected (it ships byte-exact and the next flush supersedes it),
	// so these separate it from an error rather than reporting one.
	LinesParsed     int
	LinesRawScanned int
}

// Density is bytes redacted over bytes total. Recorded per object so downstream can
// drop shredded objects, and so a density jump names the rule that went haywire.
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

// Scrubber is a compiled, reusable redaction engine.
type Scrubber struct {
	patterns []gatedPattern

	// The one heuristic detector, nil when generic-entropy is not configured. It
	// mistakes structure for secrets, so the engine consults exemptions BEFORE it.
	entropy *entropyMatcher

	// The username the path-user rewriter replaces, empty when none is configured. Not a
	// detector, so it runs everywhere including on exempt fields.
	pathUser string

	keyNames *keyNameMatcher
	exempt   *ExemptionSet

	// Answers every pattern matcher's keyword question in one pass; read-only once
	// built, so a Scrubber stays safe to share.
	prefilter *packs.Prefilter

	// The slowest single Scrub this Scrubber has served, and the payload that caused it. Atomic
	// because one Scrubber serves every worker. A pathological input can make a pattern backtrack
	// for seconds without erroring, which looks like a stalled install and nothing else reports it.
	slowestNanos atomic.Int64
	slowestBytes atomic.Int64
}

// Slowest reports the worst Scrub seen so far and the payload size behind it. Duration alone says
// little -- a large file is legitimately slow -- so the size travels with it.
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

// gatedMatcher runs high-confidence patterns behind the shared keyword prefilter.
// It takes no field path: structural exemptions must never suppress pattern matches.
type gatedMatcher interface {
	MatchScannedIn(value string, scan *packs.ValueScan) []Span
}

// gatedPattern pairs a matcher with its gate in the shared prefilter.
type gatedPattern struct {
	m    gatedMatcher
	gate packs.Gate
}

// New compiles a Scrubber. A pack named in config but absent from the corpus is an
// error: running with fewer rules than configured must not be reachable by omission.
func New(cfg Config) (*Scrubber, error) {
	s := &Scrubber{exempt: NewExemptionSet(cfg.Exemptions)}
	// Rejected rather than clamped: the scanner would read a negative floor as "every
	// run", the opposite of what lowering a threshold means.
	if cfg.Entropy.MinLength < 0 {
		return nil, fmt.Errorf("scrub: entropy min_length %d is negative", cfg.Entropy.MinLength)
	}

	// One automaton over every rule's keywords; only here knows the whole ladder.
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
	// nil stems yield AlwaysGate, so a non-ASCII configured name is still redacted, just
	// not prefiltered on bytes that cannot represent it.
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

// Scrub redacts a payload. Errors returned here are engine errors and fail closed; a
// line that does not parse is NOT an error but raw-text scanned and counted in
// LinesRawScanned, which is what lets a torn tail still ship.
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
			// Syntax errors, torn tails and over-deep records belong to the raw scanner.
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

// scrubRawText applies patterns and path rewrites without heuristics: raw text has no field exemptions.
func (s *Scrubber) scrubRawText(text string, res *Result, scan *packs.ValueScan) string {
	plan := s.planValueWith(text, nil, "", scan)
	res.record(plan.redacted, plan.hits)
	return plan.apply(text)
}
