package transforms

import (
	"math"
	"regexp"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// EntropyConfig tunes the generic-entropy backstop, the rule most likely to eat content, not secrets.
type EntropyConfig struct {
	MinLength int

	MinBitsPerChar float64

	// Pure hex tops out at 4.0 bits per character, so the base64 threshold would never fire on it.
	MinBitsPerCharHex float64
}

// DefaultEntropyConfig is the baseline that calibration_test.go's seeded corpus checks.
func DefaultEntropyConfig() EntropyConfig {
	return EntropyConfig{
		MinLength:         24,
		MinBitsPerChar:    4.2,
		MinBitsPerCharHex: 3.8,
	}
}

// entropyMatcher is the backstop for high-entropy strings no pattern claimed. Callers must check
// exemptions first: redacting a uuid or tool_use_id breaks the causal DAG and the subagent join.
type entropyMatcher struct {
	cfg EntropyConfig

	// At least 1: a zero-length candidate scores no entropy.
	minRun int

	minDistinct, minDistinctHex int

	// Delimited substrings that mark a candidate as the scrubber's own output; see Match.
	skip []string
}

func newEntropyMatcher(cfg EntropyConfig, username string) *entropyMatcher {
	skip := []string{formats.UserPlaceholder, sentinelPrefix}
	if len(username) >= 2 {
		// Same floor as pathUserReplacementSpans: a one-letter name would skip half the alphabet.
		skip = append(skip, username)
	}
	minRun := cfg.MinLength
	if minRun < 1 {
		minRun = 1
	}
	return &entropyMatcher{
		cfg:            cfg,
		minRun:         minRun,
		minDistinct:    entropyFloor(cfg.MinBitsPerChar),
		minDistinctHex: entropyFloor(cfg.MinBitsPerCharHex),
		// "/" is NOT a candidate byte: whole path prefixes made 55% of hits on a real archive. The
		// known escape, a base64 secret split by slashes, is TestBareBase64WithSlashIsAKnownEscape.
		skip: skip,
	}
}

// isCandidateByte is base64url and hex plus "+" and "="; see newEntropyMatcher for why not "/".
func isCandidateByte(c byte) bool {
	return isAlnumByte(c) || c == '+' || c == '=' || c == '_' || c == '-'
}

const entropySymbols = 66

// entropyHexBit marks a hex-digit byte; the low bits carry 1 + its rank, 0 meaning out of class.
const entropyHexBit = 0x80

// 128 rather than 67 so the compiler can prove a slot with the hex bit cleared is in range.
const entropyHistSlots = 128

// entropyClass tabulates isCandidateByte in ascending byte order: float addition does not
// associate, so rank order keeps the histogram sums bit-for-bit stable.
var entropyClass = buildEntropyClass()

func buildEntropyClass() [256]uint8 {
	var t [256]uint8
	rank := uint8(0)
	for c := 0; c < 256; c++ {
		b := byte(c)
		if !isCandidateByte(b) {
			continue
		}
		rank++
		v := rank
		if isHexByte(b) {
			v |= entropyHexBit
		}
		t[c] = v
	}
	return t
}

func isHexByte(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// entropyFloor is the fewest distinct symbols that could reach threshold, since d symbols score at
// most log2(d). The 1e-9 slack exceeds rounding, so nothing the exact loop accepts is dropped.
func entropyFloor(threshold float64) int {
	for d := 1; d <= entropySymbols; d++ {
		if math.Log2(float64(d)) >= threshold-1e-9 {
			return d
		}
	}
	return entropySymbols + 1
}

func (m *entropyMatcher) RuleID() string { return "generic-entropy" }

func (m *entropyMatcher) Match(value string) []Span {
	if len(value) < m.cfg.MinLength {
		return nil
	}
	var out []Span
	// A run must cover a grid point, so probing every minRun'th byte finds the same runs in order.
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
		// Entropy first: one histogram pass rejects nearly everything the skip search would.
		if !m.clears(candidate) {
			continue
		}
		// Idempotency: __USER__ and __REDACTED ADD entropy, so a second pass would eat the first's output.
		if m.skipsCandidate(candidate) {
			continue
		}
		out = append(out, Span{Start: start, End: i, RuleID: m.RuleID()})
	}
	return out
}

func (m *entropyMatcher) skipsCandidate(candidate string) bool {
	for _, s := range m.skip {
		if containsDelimited(candidate, s) {
			return true
		}
	}
	return false
}

// containsDelimited uses formats.ApplyUserPlaceholder's boundary rule: a username mid-run earns no skip.
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

// clears lets exactEntropyBits decide inside the slack band. The histogram is local, so a shared
// *Scrubber stays safe across goroutines.
func (m *entropyMatcher) clears(candidate string) bool {
	var counts [entropyHistSlots]int32
	distinct := 0
	// One AND per byte instead of a branch that mixed-alphabet candidates mispredict.
	hexAll := uint8(0xff)
	for i := 0; i < len(candidate); i++ {
		class := entropyClass[candidate[i]]
		hexAll &= class
		slot := uint(class &^ entropyHexBit)
		if counts[slot] == 0 {
			distinct++
		}
		counts[slot]++
	}
	threshold, floor := m.cfg.MinBitsPerChar, m.minDistinct
	if hexAll&entropyHexBit != 0 {
		threshold, floor = m.cfg.MinBitsPerCharHex, m.minDistinctHex
	}
	if threshold <= 0 {
		return false
	}
	if distinct < floor {
		return false
	}
	total := float64(len(candidate))
	est := estimateEntropyBits(&counts, total)
	if est >= threshold+entropyEstSlack {
		return true
	}
	if est < threshold-entropyEstSlack {
		return false
	}
	return exactEntropyBits(&counts, total) >= threshold
}

// estimateEntropyBits uses H = log2(T) - (1/T)*sum(c*log2(c)) so a table answers the logarithms.
// Not exact in float64, so it is trusted only outside entropyEstSlack.
func estimateEntropyBits(counts *[entropyHistSlots]int32, total float64) float64 {
	weighted := 0.0
	for _, c := range counts[:entropySymbols+1] {
		n := uint(c)
		if n < log2SmallMax {
			weighted += nLog2Table[n]
			continue
		}
		weighted += float64(n) * math.Log2(float64(n))
	}
	return math.Log2(total) - weighted/total
}

// exactEntropyBits is the Shannon sum the thresholds were fitted against; its rank order matters.
func exactEntropyBits(counts *[entropyHistSlots]int32, total float64) float64 {
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// The estimate and the exact sum differ by ~5e-13 at worst.
const entropyEstSlack = 1e-9

const log2SmallMax = 1024

var nLog2Table = buildNLog2Table()

func buildNLog2Table() (nLog2 [log2SmallMax]float64) {
	for i := 1; i < log2SmallMax; i++ {
		nLog2[i] = float64(i) * math.Log2(float64(i))
	}
	return nLog2
}

// keyNameMatcher redacts a value by its name, not its shape (`printenv` output). It scans exempt
// fields too, since AWS_SECRET_ACCESS_KEY is a secret wherever it appears; the key name survives.
type keyNameMatcher struct {
	re *regexp.Regexp

	// Uppercased once, so MatchesKeyName folds only the key it is given.
	names []configuredName

	// Lower-cased literals ("_token" for *_TOKEN) the automaton checks before re. Accepted loss: re's
	// (?i) also folds non-ASCII runes (Kelvin sign) the automaton misses; nil means re always runs.
	stems []string
}

// DefaultSecretKeyNames is the starting set; config additions only make scrubbing stricter.
func DefaultSecretKeyNames() []string {
	return []string{
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ACCESS_KEY_ID",
		"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
		"GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
		"STRIPE_SECRET_KEY", "DATABASE_URL", "REDIS_URL",
		"*_TOKEN", "*_SECRET", "*_PASSWORD", "*_APIKEY", "*_API_KEY",
		"*_PRIVATE_KEY", "*_CREDENTIALS", "*_PASSWD",
	}
}

type configuredName struct {
	upper  string
	suffix bool
}

func newKeyNameMatcher(names []string) *keyNameMatcher {
	alts := make([]string, 0, len(names))
	stems := make([]string, 0, len(names))
	configured := make([]configuredName, len(names))
	unfiltered := false
	for i, n := range names {
		literal := n
		if rest, ok := strings.CutPrefix(n, "*"); ok {
			literal = rest
			configured[i].suffix = true
			alts = append(alts, `[A-Za-z0-9_]*`+regexp.QuoteMeta(rest))
		} else {
			alts = append(alts, regexp.QuoteMeta(n))
		}
		configured[i].upper = strings.ToUpper(literal)
		if literal == "" || !isASCII(literal) {
			unfiltered = true
			continue
		}
		stems = append(stems, strings.ToLower(literal))
	}
	if unfiltered || len(stems) == 0 {
		stems = nil
	}
	// NAME=value, NAME: value, NAME = "value"; the value stops at separators so it never swallows a line.
	pattern := `(?i)\b(?:` + strings.Join(alts, "|") + `)\b\s*[:=]\s*"?([^\s"',;)]+)"?`
	return &keyNameMatcher{re: regexp.MustCompile(pattern), names: configured, stems: stems}
}

func (m *keyNameMatcher) RuleID() string { return "key-name" }

// MatchScannedIn ignores the shared PII walk, which has no candidate shape for this matcher.
func (m *keyNameMatcher) MatchScannedIn(value string, _ *packs.ValueScan) []Span {
	var out []Span
	for _, loc := range m.re.FindAllStringSubmatchIndex(value, -1) {
		if len(loc) < 4 || loc[2] < 0 {
			continue
		}
		out = append(out, Span{Start: loc[2], End: loc[3], RuleID: m.RuleID()})
	}
	return out
}

// MatchesKeyName reports whether a JSON key names a secret, redacting the whole value. Configured
// names match as the environment spells them, field names as words (see keyname.go).
func (m *keyNameMatcher) MatchesKeyName(key string) bool {
	if key == "" {
		return false
	}
	if matchesSecretKeyName(key) {
		return true
	}
	upper := strings.ToUpper(key)
	for _, n := range m.names {
		if n.suffix && strings.HasSuffix(upper, n.upper) || !n.suffix && upper == n.upper {
			return true
		}
	}
	return false
}

func isAlnumByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
