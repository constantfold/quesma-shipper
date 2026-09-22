package packs

import (
	"fmt"
	"unicode/utf8"
)

// Prefilter matches keywords in one ASCII-folded pass using an Aho-Corasick automaton.
type Prefilter struct {
	root *keywordNode
}

type keywordNode struct {
	next [utf8.RuneSelf]*keywordNode
	out  Seen
	fail *keywordNode
}

// Gate identifies one registered keyword set, asked of Seen before its matcher runs.
type Gate int32

// AlwaysGate belongs to a matcher with nothing to prefilter on: it runs on every value.
const AlwaysGate Gate = -1

const (
	// maxGates bounds Seen to a fixed-size value type, which is what makes a scan
	// allocation-free. Exceeding it is a loud build error, never a wider bitset.
	maxGates  = 256
	seenWords = maxGates / 64
)

// Seen is one scan's answer: the gates whose keywords occur in the scanned value.
type Seen struct {
	bits [seenWords]uint64
}

// Has reports whether the gate's keyword set was present.
func (s *Seen) Has(g Gate) bool {
	if g < 0 {
		return true
	}
	return s.bits[g>>6]&(uint64(1)<<uint(g&63)) != 0
}

func (s *Seen) or(o *Seen) {
	for i := range s.bits {
		s.bits[i] |= o.bits[i]
	}
}

func (s *Seen) set(g Gate) {
	s.bits[g>>6] |= uint64(1) << uint(g&63)
}

// PrefilterBuilder collects keyword sets and compiles them into one Prefilter. Registration
// order fixes gate ids and insertion order fixes the trie, so the automaton is deterministic.
type PrefilterBuilder struct {
	keywords []gatedKeyword
	gates    int
}

type gatedKeyword struct {
	folded string
	gate   Gate
}

// NewPrefilterBuilder starts an empty build.
func NewPrefilterBuilder() *PrefilterBuilder { return &PrefilterBuilder{} }

// AddKeywords registers a rule's keyword set and returns its gate; an empty set means the
// rule declares no keywords and always runs.
func (b *PrefilterBuilder) AddKeywords(keywords []string) (Gate, error) {
	if len(keywords) == 0 {
		return AlwaysGate, nil
	}
	if b.gates >= maxGates {
		return 0, fmt.Errorf("packs: prefilter holds %d keyword gates, the fixed-size limit; widen Seen", maxGates)
	}
	g := Gate(b.gates)
	for _, k := range keywords {
		if k == "" {
			return 0, fmt.Errorf("packs: prefilter: empty keyword: a marker present in every value is not a prefilter")
		}
		folded, err := foldKeyword(k)
		if err != nil {
			return 0, err
		}
		b.keywords = append(b.keywords, gatedKeyword{folded: folded, gate: g})
	}
	b.gates++
	return g, nil
}

// foldKeyword lower-cases an ASCII keyword and rejects anything else loudly: the automaton
// scans bytes, so a multi-byte rune would leave its rule quietly unprefiltered.
func foldKeyword(k string) (string, error) {
	out := make([]byte, len(k))
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c >= utf8.RuneSelf {
			return "", fmt.Errorf("packs: prefilter: keyword %q is not ASCII: keyword matching folds bytes, not runes", k)
		}
		out[i] = asciiLower(c)
	}
	return string(out), nil
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// Build completes missing transitions through failure links in breadth-first order.
func (b *PrefilterBuilder) Build() *Prefilter {
	root := &keywordNode{}
	for _, k := range b.keywords {
		n := root
		for i := 0; i < len(k.folded); i++ {
			c := k.folded[i]
			if n.next[c] == nil {
				n.next[c] = &keywordNode{}
			}
			n = n.next[c]
		}
		n.out.set(k.gate)
	}
	queue := []*keywordNode{root}
	for i := 0; i < len(queue); i++ {
		n := queue[i]
		for c, child := range n.next {
			fallback := root
			if n != root {
				fallback = n.fail.next[c]
			}
			if child == nil {
				n.next[c] = fallback
				continue
			}
			child.fail = fallback
			child.out.or(&fallback.out)
			queue = append(queue, child)
		}
	}
	return &Prefilter{root: root}
}

// Scan reads immutable transitions, so a filter is safe to share across goroutines.
func (p *Prefilter) Scan(value string) Seen {
	var seen Seen
	state := p.root
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= utf8.RuneSelf {
			state = p.root
			continue
		}
		state = state.next[asciiLower(c)]
		seen.or(&state.out)
	}
	return seen
}
