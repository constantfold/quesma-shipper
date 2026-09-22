package transforms

import (
	"math"
	"slices"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
)

// EntropyConfig tunes the generic-entropy backstop, the rule most likely to start eating content
// rather than secrets.
type EntropyConfig struct {
	MinLength int

	// For base64 and base64url candidates, whose 64-symbol alphabet tops out at 6 bits per char.
	MinBitsPerChar float64

	// For pure-hex candidates: 16 symbols cap entropy at 4.0 bits, under a shared 4.2 threshold.
	MinBitsPerCharHex float64
}

// DefaultEntropyConfig is the calibrated baseline; calibration_test.go holds it to account.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		MinLength:         24,
		MinBitsPerChar:    4.2,
		MinBitsPerCharHex: 3.8,
	}
}

// entropyMatcher is the backstop for high-entropy strings no pattern rule claimed. The engine
// checks exemptions before calling it: redacting a uuid or a tool_use_id kills the causal DAG.
type entropyMatcher struct {
	cfg    EntropyConfig
	minRun int // candidate length floor, at least 1

	// Substrings whose delimited presence marks a candidate as the scrubber's own output.
	skip []string
}

func newEntropyMatcher(cfg EntropyConfig, username string) *entropyMatcher {
	skip := []string{formats.UserPlaceholder, sentinelPrefix}
	// Same floor as pathUserReplacementSpans: a one-letter name would skip half the alphabet.
	if len(username) >= 2 {
		skip = append(skip, username)
	}
	return &entropyMatcher{cfg: cfg, minRun: max(cfg.MinLength, 1), skip: skip}
}

// isCandidateByte is the entropy candidate alphabet: base64url and hex, plus the "+" and "=" of
// standard base64. "/" is deliberately NOT in it: with it a candidate is a whole path prefix,
// 55% of all redaction hits on a real archive. The accepted residual, a std-base64 secret whose
// slashes split it under MinLength, is recorded in TestBareBase64WithSlashIsAKnownEscape.
func isCandidateByte(c byte) bool {
	return isAlnumByte(c) || c == '+' || c == '=' || c == '_' || c == '-'
}

const (
	// entropySymbols is the candidate alphabet size.
	entropySymbols = 66
	// entropyHexBit marks a class entry whose byte is a hex digit; the low bits carry 1 + the
	// byte's rank in the alphabet, 0 meaning out of class.
	entropyHexBit = 0x80
	// 128 rather than 67 slots, so the compiler can prove a slot with the hex bit cleared in range.
	entropyHistSlots = 128
)

// entropyClass tabulates isCandidateByte. Ranks ascend in byte order so the histogram's partial
// sums are bit-for-bit stable: float addition does not associate.
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

// isHexByte marks the runs that earn MinBitsPerCharHex rather than MinBitsPerChar.
func isHexByte(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (m *entropyMatcher) RuleID() string { return "generic-entropy" }

// Match probes every minRun'th byte, since a candidate run must cover a grid point, and must
// find exactly the runs, in order, a byte-at-a-time scan would.
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
		// Entropy first, since one histogram pass rejects nearly everything. The skip is required
		// for idempotency: __USER__ and __REDACTED ADD entropy, and without it a second pass eats
		// the first pass's output. The username is that output one pass earlier.
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

// containsDelimited requires non-alphanumeric neighbours, as formats.ApplyUserPlaceholder does,
// so a token that merely embeds the username mid-run never earns the skip.
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
		leftOK := i == 0 || !isAlnumByte(s[i-1])
		rightOK := i+len(sub) == len(s) || !isAlnumByte(s[i+len(sub)])
		if leftOK && rightOK {
			return true
		}
		// One byte on, so an occurrence starting inside this one is still seen.
		i++
	}
	return false
}

// clears uses the calibrated Shannon sum, in symbol order, for both alphabets.
func (m *entropyMatcher) clears(candidate string) bool {
	var counts [entropyHistSlots]int32
	// The hex verdict is one AND per byte, not a branch mixed-alphabet candidates mispredict.
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

// exactEntropyBits is the Shannon sum the thresholds were fitted against: ascending symbol-rank
// order, accumulated left to right, which is a correctness property.
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
