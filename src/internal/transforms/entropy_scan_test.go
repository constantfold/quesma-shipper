package transforms

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The optimized scan must find the same candidates as a byte walk.

// refMatch is the byte-at-a-time run walk the grid scan replaced: every byte inspected, every
// maximal in-class run of at least minRun emitted.
func refMatch(m *entropyMatcher, value string) []Span {
	if len(value) < m.cfg.MinLength {
		return nil
	}
	if m.cfg.MinBitsPerChar <= 0 && m.cfg.MinBitsPerCharHex <= 0 {
		return nil
	}
	var out []Span
	for i := 0; i < len(value); {
		if entropyClass[value[i]] == 0 {
			i++
			continue
		}
		start := i
		for i < len(value) && entropyClass[value[i]] != 0 {
			i++
		}
		if i-start < m.minRun {
			continue
		}
		candidate := value[start:i]
		if m.skipsCandidate(candidate) {
			continue
		}
		if !m.clears(candidate) {
			continue
		}
		out = append(out, Span{Start: start, End: i, RuleID: m.RuleID()})
	}
	return out
}

func TestEntropyGridScanFindsTheSameRunsAsTheByteWalk(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	// Fragments chosen so runs land on and across the grid: separators of every length, runs just
	// under and just over the floor, the scrubber's own output.
	frag := []string{
		"a", "-", "/", ".", " ", ":", "_", "==",
		"0123456789abcdef", "AKIA1234567890ABCDEF", "__USER__", "__REDACTED:card-pan__",
		"devuser", "/Users/devuser/git/proj", "sk-ant-api03-QmFzZTY0U2VjcmV0",
		"7f3c9a1b2e5d8046", "the quick brown fox", "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=",
		strings.Repeat("A", 40), strings.Repeat("ab", 20),
	}
	cfgs := []EntropyConfig{
		DefaultEntropyConfig(),
		{MinLength: 1, MinBitsPerChar: 4.2, MinBitsPerCharHex: 3.8},
		{MinLength: 2, MinBitsPerChar: 3.0, MinBitsPerCharHex: 3.0},
		{MinLength: 7, MinBitsPerChar: 4.2, MinBitsPerCharHex: 3.8},
		{MinLength: 64, MinBitsPerChar: 4.2, MinBitsPerCharHex: 3.8},
		{MinLength: 0, MinBitsPerChar: 4.2, MinBitsPerCharHex: 3.8},
	}
	for _, cfg := range cfgs {
		m := newEntropyMatcher(cfg, "devuser")
		for i := 0; i < 40000; i++ {
			var b strings.Builder
			for j := rng.Intn(8); j >= 0; j-- {
				b.WriteString(frag[rng.Intn(len(frag))])
			}
			v := b.String()
			got, want := m.Match(v), refMatch(m, v)
			require.Len(t, got, len(want))
			for k := range got {
				if got[k] != want[k] {
					t.Fatalf("MinLength %d, %q: span %d = %v, want %v", cfg.MinLength, v, k, got[k], want[k])
				}
			}
		}
	}
}

// Scoring retains the original summation order, including long, uneven candidates.
func TestEntropyExactScoreMatchesTheWideHistogram(t *testing.T) {
	rng := rand.New(rand.NewSource(37))
	alphabet := candidateAlphabet()
	for i := 0; i < 200000; i++ {
		n := 1 + rng.Intn(400)
		width := 1 + rng.Intn(len(alphabet))
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = alphabet[rng.Intn(width)]
		}
		s := string(buf)

		var counts [entropyHistSlots]int32
		for j := 0; j < len(s); j++ {
			counts[uint(entropyClass[s[j]]&^entropyHexBit)]++
		}
		require.Equal(t, refShannonBits(s), exactEntropyBits(&counts, float64(len(s))), "candidate %q", s)
	}
}
