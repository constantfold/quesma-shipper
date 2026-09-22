package transforms

import (
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The grid scan, narrow histogram and fused hex test are replayed against the originals, copied here.

func refIsHexRun(s string) bool {
	return s != "" && strings.Trim(s, "0123456789abcdefABCDEF") == ""
}

func refShannonBits(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	bits := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		bits -= p * math.Log2(p)
	}
	return bits
}

func refClears(cfg EntropyConfig, candidate string) bool {
	threshold := cfg.MinBitsPerChar
	if refIsHexRun(candidate) {
		threshold = cfg.MinBitsPerCharHex
	}
	if threshold <= 0 {
		return false
	}
	return refShannonBits(candidate) >= threshold
}

func TestEntropyClassTableMatchesTheByteTests(t *testing.T) {
	rank := 0
	for c := 0; c < 256; c++ {
		b := byte(c)
		got := entropyClass[c]
		if !isCandidateByte(b) {
			require.Equalf(t, uint8(0), got, "byte %d out of class but tabulated as %d", c, got)
			continue
		}
		rank++
		require.Equalf(t, rank, int(got&^entropyHexBit), "byte %d: rank %d, want %d", c, got&^entropyHexBit, rank)
		require.Equalf(t, isHexByte(b), (got&entropyHexBit != 0), "byte %d: hex bit %v, want %v", c, got&entropyHexBit != 0, isHexByte(b))
	}
	require.Equalf(t, entropySymbols, rank, "alphabet has %d symbols, entropySymbols is %d", rank, entropySymbols)
}

// Bit-identical, not merely close: a last-ulp difference at the threshold flips a redaction.
func TestEntropyScoreIsBitIdenticalToTheWideHistogram(t *testing.T) {
	rng := rand.New(rand.NewSource(37))
	alphabet := candidateAlphabet()
	m := newEntropyMatcher(DefaultEntropyConfig(), "")
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
		require.Equal(t, refClears(m.cfg, s), m.clears(s), "clears(%q), bits %v", s, refShannonBits(s))
	}
}

// Configured thresholds must preserve decisions at and around log2(d) boundaries.
func TestEntropyDecisionsHoldAtBoundaryThresholds(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	alphabet := candidateAlphabet()
	hex := []byte("0123456789abcdefABCDEF")
	var thresholds []float64
	for d := 1; d <= entropySymbols; d++ {
		v := math.Log2(float64(d))
		thresholds = append(thresholds, v, math.Nextafter(v, 0), math.Nextafter(v, 10))
	}
	thresholds = append(thresholds, 0, -1, 3.8, 4.2, 6)
	for _, th := range thresholds {
		cfg := EntropyConfig{MinLength: 1, MinBitsPerChar: th, MinBitsPerCharHex: th}
		m := newEntropyMatcher(cfg, "")
		for i := 0; i < 4000; i++ {
			pool := alphabet
			if i%2 == 0 {
				pool = hex
			}
			// Uniform draws over d symbols land closest to the log2(d) boundary.
			d := 1 + rng.Intn(len(pool))
			n := d * (1 + rng.Intn(4))
			buf := make([]byte, 0, n)
			for j := 0; j < n; j++ {
				buf = append(buf, pool[j%d])
			}
			require.Equal(t, refClears(cfg, string(buf)), m.clears(string(buf)), "threshold %v: clears(%q)", th, buf)
		}
	}
}

func TestContainsDelimitedMatchesTheNaiveScan(t *testing.T) {
	naive := func(s, sub string) bool {
		if sub == "" {
			return false
		}
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] != sub {
				continue
			}
			leftOK := i == 0 || !isAlnumByte(s[i-1])
			rightOK := i+len(sub) == len(s) || !isAlnumByte(s[i+len(sub)])
			if leftOK && rightOK {
				return true
			}
		}
		return false
	}
	rng := rand.New(rand.NewSource(13))
	subs := []string{"", "a", "aa", "__USER__", "__REDACTED", "quinn", "-", "aba"}
	bits := []string{"a", "b", "-", "_", "__USER__", "__REDACTED", "quinn", "aba", ":", "9"}
	for i := 0; i < 200000; i++ {
		n := rng.Intn(6)
		s := ""
		for j := 0; j < n; j++ {
			s += bits[rng.Intn(len(bits))]
		}
		sub := subs[rng.Intn(len(subs))]
		require.Equal(t, naive(s, sub), containsDelimited(s, sub), "containsDelimited(%q, %q)", s, sub)
	}
}

func candidateAlphabet() []byte {
	alphabet := make([]byte, 0, entropySymbols)
	for c := 0; c < 256; c++ {
		if isCandidateByte(byte(c)) {
			alphabet = append(alphabet, byte(c))
		}
	}
	return alphabet
}

// refMatch is the byte-at-a-time run walk the grid scan replaced.
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
		if candidate := value[start:i]; !m.skipsCandidate(candidate) && m.clears(candidate) {
			out = append(out, Span{Start: start, End: i, RuleID: m.RuleID()})
		}
	}
	return out
}

func TestEntropyGridScanFindsTheSameRunsAsTheByteWalk(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	// Runs landing on and across the grid, around the floor, and the scrubber's own output.
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
			require.Equal(t, refMatch(m, v), m.Match(v), "MinLength %d, %q", cfg.MinLength, v)
		}
	}
}
