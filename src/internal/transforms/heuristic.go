package transforms

import (
	"math"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// EntropyConfig tunes the generic-entropy backstop; hex gets its own threshold, as 16 symbols cap it at 4 bits.
type EntropyConfig struct {
	MinLength         int
	MinBitsPerChar    float64
	MinBitsPerCharHex float64
}

// DefaultEntropyConfig is the calibrated baseline; calibration_test.go holds it to account.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{MinLength: 24, MinBitsPerChar: 4.2, MinBitsPerCharHex: 3.8}
}

// entropyMatcher backstops high-entropy strings; exemptions come first, as redacting a uuid kills the DAG.
type entropyMatcher struct {
	cfg    EntropyConfig
	minRun int      // candidate length floor, at least 1
	skip   []string // delimited, these mark a candidate as the scrubber's own output
}

func newEntropyMatcher(cfg EntropyConfig, username string) *entropyMatcher {
	skip := []string{formats.UserPlaceholder, sentinelPrefix}
	// Same floor as pathUserReplacementSpans: a one-letter name would skip half the alphabet.
	if len(username) >= 2 {
		skip = append(skip, username)
	}
	return &entropyMatcher{cfg: cfg, minRun: max(cfg.MinLength, 1), skip: skip}
}

// isCandidateByte is base64url plus "+" and "=". Not "/": whole path prefixes were 55% of hits on a real
// archive; the residual is recorded in TestBareBase64WithSlashIsAKnownEscape.
func isCandidateByte(c byte) bool {
	return isAlnumByte(c) || c == '+' || c == '=' || c == '_' || c == '-'
}

// A class entry is 1 + alphabet rank (0 is out) plus the hex bit; 128 slots elide the bounds check.
const (
	entropySymbols   = 66
	entropyHexBit    = 0x80
	entropyHistSlots = 128
)

// entropyClass tabulates isCandidateByte, ranks ascending in byte order.
var entropyClass = func() (t [256]uint8) {
	rank := uint8(0)
	for c := 0; c < 256; c++ {
		if !isCandidateByte(byte(c)) {
			continue
		}
		rank++
		t[c] = rank
		if isHexByte(byte(c)) {
			t[c] |= entropyHexBit
		}
	}
	return t
}()

func isHexByte(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (m *entropyMatcher) RuleID() string { return "generic-entropy" }

// Match probes every minRun'th byte, which any candidate covers, finding exactly the byte walk's runs.
func (m *entropyMatcher) Match(value string) []Span {
	if len(value) < m.cfg.MinLength {
		return nil
	}
	var out []Span
	scanned := 0
	for p := m.minRun - 1; p < len(value); p += m.minRun {
		if p < scanned || entropyClass[value[p]] == 0 {
			continue
		}
		start := p
		for start > scanned && entropyClass[value[start-1]] != 0 {
			start--
		}
		i := p + 1
		for i < len(value) && entropyClass[value[i]] != 0 {
			i++
		}
		scanned = i
		if i-start < m.minRun {
			continue
		}
		candidate := value[start:i]
		// Entropy first, as it rejects nearly everything; the skip keeps a re-scrub idempotent.
		if !m.clears(candidate) || m.skipsCandidate(candidate) {
			continue
		}
		out = append(out, Span{Start: start, End: i, RuleID: m.RuleID()})
	}
	return out
}

func (m *entropyMatcher) skipsCandidate(candidate string) bool {
	return slices.ContainsFunc(m.skip, func(s string) bool { return containsDelimited(candidate, s) })
}

// containsDelimited requires non-alphanumeric neighbours, as formats.ApplyUserPlaceholder does.
func containsDelimited(s, sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i+len(sub) <= len(s); {
		at := strings.Index(s[i:], sub)
		if at < 0 {
			return false
		}
		i += at
		if (i == 0 || !isAlnumByte(s[i-1])) && (i+len(sub) == len(s) || !isAlnumByte(s[i+len(sub)])) {
			return true
		}
		// One byte on, so an occurrence starting inside this one is still seen.
		i++
	}
	return false
}

// clears computes the hex verdict as one AND per byte, not a branch mixed alphabets mispredict.
func (m *entropyMatcher) clears(candidate string) bool {
	var counts [entropyHistSlots]int32
	hexAll := uint8(0xff)
	for i := 0; i < len(candidate); i++ {
		class := entropyClass[candidate[i]]
		hexAll &= class
		counts[uint(class&^entropyHexBit)]++
	}
	threshold := m.cfg.MinBitsPerChar
	if hexAll&entropyHexBit != 0 {
		threshold = m.cfg.MinBitsPerCharHex
	}
	if threshold <= 0 {
		return false
	}
	return exactEntropyBits(&counts, float64(len(candidate))) >= threshold
}

// exactEntropyBits is the fitted Shannon sum; ascending rank order matters, as float addition does not associate.
func exactEntropyBits(counts *[entropyHistSlots]int32, total float64) float64 {
	h := 0.0
	for _, c := range counts[:entropySymbols+1] {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}
