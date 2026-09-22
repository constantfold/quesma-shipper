// Package packs compiles vendored redaction corpora into matchers.
// The corpora are data, so the collector does not inherit a detector’s runtime dependencies.
package packs

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

//go:embed data/*.json
var corpora embed.FS

// Names of the compiled packs.
const (
	GitleaksCore   = "gitleaks-core"
	QuesmaExtra    = "quesma-extra"
	CloudKeys      = "cloud-keys"
	PIICore        = "pii-core"
	GenericEntropy = "generic-entropy"
)

// Span is one matched byte range.
type Span struct {
	Start  int
	End    int
	RuleID string
}

type ruleSpec struct {
	ID       string   `json:"id"`
	Regex    string   `json:"regex"`
	Keywords []string `json:"keywords"`
	Capture  int      `json:"capture"`
	Checksum string   `json:"checksum"`
	Guard    string   `json:"guard"`
	Scanner  string   `json:"scanner"`
	Sweep    bool     `json:"sweep"` // keywords occur mid-match, or anchoring is a proven cost cliff
}

// corpus omits the data files' description and todo keys, which the compiler never reads.
type corpus struct {
	Pack  string     `json:"pack"`
	Rules []ruleSpec `json:"rules"`
}

// Rule is one compiled pattern rule.
type Rule struct {
	id       string
	re       *regexp.Regexp
	keywords []string
	capture  int
	checksum func(string) bool
	guard    func(value string, start, end int) bool

	// At most one fast path replaces the regex sweep, each answering exactly as it would: a byte
	// walk of its own, a slot in the shared PII walk, or an anchor on the corpus keywords.
	hand   func(value string) []Span
	fused  fusedKind
	anchor *anchorScan
}

var scanners = map[string]struct {
	fn    func(value string) []Span
	fused fusedKind
}{
	"card-pan": {nil, fusedCardPAN},
	"iban":     {nil, fusedIBAN},
	"pesel":    {nil, fusedPESEL},
	"email":    {scanEmail, fusedNone},
}

// RuleID names the rule, for engine wiring and error messages.
func (r *Rule) RuleID() string { return r.id }

// Keywords are the rule's literal markers, for registering with a shared Prefilter.
func (r *Rule) Keywords() []string { return r.keywords }

// MatchScannedIn finds every occurrence in a value the caller has already scanned for keywords,
// with scan Reset to this exact value.
func (r *Rule) MatchScannedIn(value string, scan *ValueScan) []Span {
	switch {
	case r.fused != fusedNone:
		// Guard and checksum read the scan's own bytes, so a stale scan cannot mix two strings.
		return r.checked(scan.candidates(r.fused), scan.value)
	case r.hand != nil:
		return r.checked(r.hand(value), value)
	case r.anchor != nil:
		return r.matchAnchored(value)
	}
	return r.matchSweep(value)
}

// checked filters and stamps candidates in place. A rejected one still consumed its bytes, as in FindAll.
func (r *Rule) checked(found []Span, value string) []Span {
	out := found[:0]
	for _, s := range found {
		if !r.accepts(value, s.Start, s.End) {
			continue
		}
		s.RuleID = r.id
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *Rule) accepts(value string, start, end int) bool {
	if r.guard != nil && !r.guard(value, start, end) {
		return false
	}
	return r.checksum == nil || r.checksum(value[start:end])
}

// matchSweep hands the whole value to the regex engine: the reference the fast paths are held to.
func (r *Rule) matchSweep(value string) []Span {
	var out []Span
	for _, loc := range r.re.FindAllStringSubmatchIndex(value, -1) {
		if s, ok := r.span(value, loc); ok {
			out = append(out, s)
		}
	}
	return out
}

// matchAnchored reproduces FindAll's loop by literal search: a position with no entry literal cannot
// start a match, so the leftmost candidate that verifies IS the leftmost match. A rejected
// candidate moves one byte, so a nested match stays findable.
func (r *Rule) matchAnchored(value string) []Span {
	s := r.anchor
	var cursor litCursor
	cursor.init()

	var out []Span
	for pos := 0; pos <= len(value); {
		at := cursor.next(s, value, pos)
		if at < 0 {
			break
		}
		// \b, which verify cannot see: every entry literal starts on a word byte.
		if s.wordEdge && at > 0 && isWordByte(value[at-1]) {
			pos = at + 1
			continue
		}
		loc := s.verify.FindStringSubmatchIndex(value[at:])
		if loc == nil {
			pos = at + 1
			continue
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += at
			}
		}
		if sp, ok := r.span(value, loc); ok {
			out = append(out, sp)
		}
		// A match carries an entry literal, so it is never empty.
		pos = max(loc[1], at+1)
	}
	return out
}

// span applies the capture group, which redacts the value and keeps the key name, then the checks.
func (r *Rule) span(value string, loc []int) (Span, bool) {
	start, end := loc[0], loc[1]
	if r.capture > 0 && len(loc) > 2*r.capture+1 && loc[2*r.capture] >= 0 {
		start, end = loc[2*r.capture], loc[2*r.capture+1]
	}
	if !r.accepts(value, start, end) {
		return Span{}, false
	}
	return Span{Start: start, End: end, RuleID: r.id}, true
}

var checksums = map[string]func(string) bool{
	"iban":  ibanValid,
	"pesel": peselValid,
	"pan":   panValid,
}

// A guard sees the characters around the match, for what \b cannot say.
var guards = map[string]func(value string, start, end int) bool{
	// Rejects a piece of a larger decimal number; any other dot is prose punctuation.
	"no-decimal-neighbor": func(value string, start, end int) bool {
		if start > 0 && value[start-1] == '.' {
			return false
		}
		return !(end+1 < len(value) && value[end] == '.' && value[end+1] >= '0' && value[end+1] <= '9')
	},
}

// Load compiles one pack's corpus.
func Load(pack string) ([]*Rule, error) {
	raw, err := corpora.ReadFile("data/" + pack + ".json")
	if err != nil {
		return nil, fmt.Errorf("packs: pack %q has no corpus: %w", pack, err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("packs: %s: %w", pack, err)
	}
	if c.Pack != pack {
		return nil, fmt.Errorf("packs: %s.json declares pack %q", pack, c.Pack)
	}

	out := make([]*Rule, 0, len(c.Rules))
	for _, spec := range c.Rules {
		r, err := compileSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("packs: %s rule %s: %w", pack, spec.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// compileSpec is split out of Load so tests can compile specs the corpora do not have.
func compileSpec(spec ruleSpec) (*Rule, error) {
	re, err := regexp.Compile(spec.Regex)
	if err != nil {
		return nil, err
	}
	r := &Rule{id: spec.ID, re: re, keywords: spec.Keywords, capture: spec.Capture}
	if spec.Checksum != "" {
		if r.checksum = checksums[spec.Checksum]; r.checksum == nil {
			return nil, fmt.Errorf("unknown checksum %q", spec.Checksum)
		}
	}
	if spec.Guard != "" {
		if r.guard = guards[spec.Guard]; r.guard == nil {
			return nil, fmt.Errorf("unknown guard %q", spec.Guard)
		}
	}
	if spec.Scanner != "" {
		sc, ok := scanners[spec.Scanner]
		if !ok {
			return nil, fmt.Errorf("unknown scanner %q", spec.Scanner)
		}
		// A scanner returns whole spans, so with a capture group it would redact more than its regex.
		if spec.Capture > 0 {
			return nil, fmt.Errorf("scanner %q with capture group %d", spec.Scanner, spec.Capture)
		}
		r.hand, r.fused = sc.fn, sc.fused
		// No anchor: the regex never runs.
		return r, nil
	}
	r.anchor, err = newAnchorScan(spec.Regex, spec.Keywords, spec.Sweep)
	return r, err
}

// Available lists the packs with an embedded corpus, plus the code-only heuristic pack.
func Available() []string {
	entries, err := corpora.ReadDir("data")
	if err != nil {
		return nil
	}
	out := []string{GenericEntropy}
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	slices.Sort(out)
	return out
}
