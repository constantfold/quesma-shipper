package packs

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// anchorScan finds the keywords that start every match, then verifies an anchored regex (TestAnchorMatchesSweep).
type anchorScan struct {
	verify   *regexp.Regexp // \A(?:pattern), run against value[p:], keeps every group number
	lits     []string       // the entry literals: the rule's corpus keywords
	fold     bool           // the literals match under Go's (?i) Unicode simple folding
	wordEdge bool           // the pattern opened with \b, which verify cannot check at value[p:]
}

const (
	maxAnchorLits = 8 // the litCursor's fixed scratch; the corpora carry at most five
	minAnchorLen  = 2 // a single-byte literal lands on prose constantly

	litUnscanned = -2 // litCursor positions out of band of any byte offset
	litExhausted = -1
)

// newAnchorScan returns nil when anchoring is unsound or unprofitable.
func newAnchorScan(pattern string, keywords []string, sweep bool) (*anchorScan, error) {
	if sweep || len(keywords) == 0 || len(keywords) > maxAnchorLits {
		return nil, nil
	}
	rest, fold := strings.CutPrefix(pattern, "(?i)")
	// A (?i) region anywhere but the head means the keywords' spelling is not the matches'.
	if strings.Contains(rest, "(?i") {
		return nil, nil
	}
	wordEdge := strings.HasPrefix(rest, `\b`)
	for _, k := range keywords {
		// \b before a non-word entry byte reads a byte verify cannot see; (?i) search tries two ASCII cases.
		if len(k) < minAnchorLen || !isASCII(k) || wordEdge && !isWordByte(k[0]) ||
			fold && !foldOrbitASCII(rune(asciiLower(k[0]))) {
			return nil, nil
		}
	}
	verify, err := regexp.Compile(`\A(?:` + pattern + `)`)
	if err != nil {
		// Load compiles the same pattern first; returned so a lost fast path is not silent.
		return nil, fmt.Errorf("anchor: anchored form of %q: %w", pattern, err)
	}
	return &anchorScan{verify: verify, lits: keywords, fold: fold, wordEdge: wordEdge}, nil
}

// foldOrbitASCII reports whether every rune Go's (?i) folds r with is ASCII.
func foldOrbitASCII(r rune) bool {
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// litCursor is per-call scratch holding each entry literal's next occurrence: the Rule is shared.
type litCursor struct {
	at [maxAnchorLits]int
}

func (c *litCursor) init() {
	for i := range c.at {
		c.at[i] = litUnscanned
	}
}

// next returns the lowest candidate position at or after pos, or -1 when none remains.
func (c *litCursor) next(s *anchorScan, value string, pos int) int {
	best := -1
	for i, lit := range s.lits {
		if c.at[i] == litExhausted {
			continue
		}
		if c.at[i] < pos {
			c.at[i] = s.index(value, pos, lit)
		}
		if c.at[i] >= 0 && (best < 0 || c.at[i] < best) {
			best = c.at[i]
		}
	}
	return best
}

func (s *anchorScan) index(value string, from int, lit string) int {
	var at int
	if s.fold {
		at = indexFold(value[from:], lit)
	} else {
		at = strings.Index(value[from:], lit)
	}
	if at < 0 {
		return litExhausted
	}
	return from + at
}

// indexFold is strings.Index under Go's (?i) folding, skipping by a memchr pair on the first byte.
func indexFold(s, lit string) int {
	lo, hi := foldCases(lit[0])
	for i := 0; i < len(s); {
		j := indexEitherByte(s[i:], lo, hi)
		if j < 0 {
			return -1
		}
		at := i + j
		if hasFoldPrefix(s[at:], lit) {
			return at
		}
		i = at + 1
	}
	return -1
}

func foldCases(c byte) (byte, byte) {
	switch {
	case 'a' <= c && c <= 'z':
		return c, c - ('a' - 'A')
	case 'A' <= c && c <= 'Z':
		return c, c + ('a' - 'A')
	}
	return c, c
}

func indexEitherByte(s string, a, b byte) int {
	ia := strings.IndexByte(s, a)
	if a == b || ia == 0 {
		return ia
	}
	if ia < 0 {
		return strings.IndexByte(s, b)
	}
	// Bounded by the first hit: the answer is the earlier of the two.
	if ib := strings.IndexByte(s[:ia], b); ib >= 0 {
		return ib
	}
	return ia
}

func hasFoldPrefix(s, lit string) bool {
	end := 0
	for range len(lit) {
		if end == len(s) {
			return false
		}
		_, width := utf8.DecodeRuneInString(s[end:])
		end += width
	}
	return strings.EqualFold(s[:end], lit)
}
