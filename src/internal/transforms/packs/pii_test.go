package packs

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Scanners replay against their regex on raw candidates too, so a checksum cannot mask a divergence.

// piiScannerRules returns the loaded rules that carry a hand scanner.
func piiScannerRules(t *testing.T) []*Rule {
	t.Helper()
	var out []*Rule
	for _, r := range loadedRules(t, PIICore) {
		if r.hand != nil || r.fused != fusedNone {
			out = append(out, r)
		}
	}
	// The three keywordless shapes plus email, whose keyword fires on nearly every value.
	require.Lenf(t, out, 4, "expected four pii-core rules to carry scanners, got %d", len(out))
	return out
}

// scanCandidates is the rule's byte walk before guard and checksum.
func scanCandidates(r *Rule, value string) []Span {
	if r.fused != fusedNone {
		var c ValueScan
		c.Reset(value)
		return c.candidates(r.fused)
	}
	return r.hand(value)
}

func compareScannerAndRegex(t *testing.T, r *Rule, value string) {
	t.Helper()

	// Candidates first: the spans before the checksum, where leftmost-first and non-overlap live.
	var got [][]int
	for _, s := range scanCandidates(r, value) {
		got = append(got, []int{s.Start, s.End})
	}
	require.Equal(t, r.re.FindAllStringIndex(value, -1), got, "%s candidates on %q", r.id, value)

	// Then the rule's answer, checksum and rule id included.
	require.Equal(t, r.matchSweep(value), r.MatchScanned(value), "%s spans on %q", r.id, value)
}

// Cases the fuzz would reach only by luck: value ends, separator positions, runs either side of bounds.
var piiEdgeValues = []string{
	"", " ", "-", "0", "_", "abc", "\xff", "é", "\x80\x80\x80",
	"12345678901", " 12345678901 ", "12345678901x", "x12345678901",
	"_12345678901", "12345678901_", "123456789012", "1234567890",
	"12345678901 12345678901", "12345678901-12345678901",
	"44051401359", " 44051401359", "44051401359\n", "4405140135944051401359",
	"44051401359 44051401359", "DE8937040044053201300044051401359",
	"4111111111111111", " 4111111111111111 ", "4111 1111 1111 1111",
	"4111-1111-1111-1111", "4111 1111-1111 1111", "4111  1111 1111 1111",
	"-4111111111111111-", "x4111111111111111", "4111111111111111x",
	"41111111111111111111", "411111111111111111111111111111",
	"1 2 3 4 5 6 7 8 9 0 1 2 3", "1-2-3-4-5-6-7-8-9-0-1-2-3",
	"1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3",
	"4111111111111111 4111111111111111", "0000000000000000",
	"411111111111111 1", "411111111111111-", "-411111111111111",
	"4111111111111111-1", "1-4111111111111111", "4111111111111111 1111",
	"4111 1111 1111 1111 44051401359 4111111111111111",
	"44051401359-4111 1111 1111 1111-DE89370400440532013000",
	"DE89370400440532013000", " DE89370400440532013000 ",
	"DE893704004405320130001111111111111", "GB82WEST12345698765432",
	"de89370400440532013000", "DE8937040044053201300", "XX00XXXXXXXXXXX",
	"DE89370400440532013000_", "_DE89370400440532013000",
	"DE89 3704 0044 0532 0130 00", "AB12CDEFGHIJKLMNO",
	"AB12CDEFGHIJKLM", "AB12CDEFGHIJKL", "A1B2CDEFGHIJKLMNO",
	"AB12CDEFGHIJKLMN", "AB12CDEFGHIJKLMNo", "AB12CDEFGHIJKLMN_",
	"12ABCDEFGHIJKLMNO", "AB1CDEFGHIJKLMNOP",
	strings.Repeat("9", 40), strings.Repeat("9 ", 40), strings.Repeat("9-", 40),
	strings.Repeat("A9", 40), strings.Repeat("1", 19) + "é" + strings.Repeat("1", 19),
	strings.Repeat("4111", 20), strings.Repeat("1 ", 200),
	// Email: value boundaries, clustered '@', TLD length bounds, non-ASCII either side.
	"@", "a@b.com", "@a.com", "a@", "..@a.com", "a@@b.com", "a@b@c.com",
	"a@b.com@c.de", "a@b.com1", "a@b.com_", "a@b.co.1", "a@b.c.com", "a@b..com",
	".a@b.com", "a.@b.com", "-a@b.com", "_@a.com", "1@a.com", "%@a.com",
	"a@-.com", "a@.com", "a@b.-com", "x@y.c", "x@y.cc", "x@y.c1", "@@@@",
	"a@a@a@a.com", "a@b.comX@d.ee", "a@b.co@d.ee", "\xffa@b.com", "a@b.com\xff",
	"użytkownik@przykład.com", "用户@example.com",
	"mail to foo.bar%baz+q@sub.example.co.uk!", "a@b.com.", "a@b.com-",
	"aaaa@bbbb.cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
}

// The edges, then the volume: digit soup with separators everywhere, valid and invalid checksums.
func TestPIIScannersAgreeWithTheirRegex(t *testing.T) {
	values := slices.Clone(piiEdgeValues)
	rng := rand.New(rand.NewSource(20260816))
	for i := 0; i < 40000; i++ {
		values = append(values, randPIIValue(rng))
	}
	for _, r := range piiScannerRules(t) {
		for _, v := range values {
			compareScannerAndRegex(t, r, v)
		}
	}
}

// Exhaustive over five structural bytes, then random '@'-dense values.
func TestEmailScannerAgreesWithTheRegex(t *testing.T) {
	email := ruleByID(t, PIICore, "email")
	alphabet := []string{"@", ".", "-", "_", "%", "a", "c", "o", "m", "0", "!", "Z"}
	var walk func(prefix string, depth int)
	walk = func(prefix string, depth int) {
		compareScannerAndRegex(t, email, prefix)
		if depth == 0 {
			return
		}
		for _, s := range alphabet {
			walk(prefix+s, depth-1)
		}
	}
	walk("", 5)

	tokens := []string{
		"@", "a", "Z", "0", "9", ".", "-", "_", "%", "+", "!", " ", "=", "/", "\"",
		"com", "co", "c", "example", "é", "\xff", "\n", "\t", "..", "@@",
	}
	rng := rand.New(rand.NewSource(20260816))
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for n := rng.Intn(24); n > 0; n-- {
			b.WriteString(tokens[rng.Intn(len(tokens))])
		}
		compareScannerAndRegex(t, email, b.String())
	}
}

// A slot of one reused scan answers as alone, whichever rule walked it and whatever it held before.
func TestFusedScanAgreesWithStandaloneScanners(t *testing.T) {
	var rules []*Rule
	for _, r := range loadedRules(t, PIICore) {
		if r.fused != fusedNone {
			rules = append(rules, r)
		}
	}
	require.Len(t, rules, 3)
	values := slices.Clone(piiEdgeValues)
	rng := rand.New(rand.NewSource(20260817))
	for i := 0; i < 20000; i++ {
		values = append(values, randPIIValue(rng))
	}

	var scan ValueScan
	for _, v := range values {
		for first := range rules {
			scan.Reset(v)
			for k := range rules {
				r := rules[(first+k)%len(rules)]
				require.Equal(t, r.MatchScanned(v), r.MatchScannedIn(v, &scan), "%s on %q after %s asked first", r.id, v, rules[first].id)
			}
		}
	}
}

// A rule with no slot must answer the same whatever the scan holds.
func TestNonFusedRuleIgnoresTheScan(t *testing.T) {
	var scan ValueScan
	scan.Reset("4111111111111111 44051401359 DE89370400440532013000")
	scan.candidates(fusedPESEL) // force the walk, so the slots are non-empty
	const v = "mail jane@example.com and 4111111111111111"
	for _, r := range loadedRules(t, PIICore) {
		if r.fused == fusedNone {
			require.Equal(t, r.MatchScanned(v), r.MatchScannedIn(v, &scan), "%s with a stale scan", r.id)
		}
	}
}

// The one combination that would redact a different span than the pattern must not compile.
func TestPIIScannerRejectsACaptureGroup(t *testing.T) {
	_, err := compileSpec(ruleSpec{ID: "x", Regex: `\b[0-9]{11}\b`, Scanner: "pesel", Capture: 1})
	require.Error(t, err, "a scanner paired with a capture group must not compile")
	_, err = compileSpec(ruleSpec{ID: "x", Regex: `\b[0-9]{11}\b`, Scanner: "nope"})
	require.Error(t, err, "an unknown scanner must not compile")
}

var piiFragments = []string{
	"0", "1", "9", " ", "-", "_", "x", "X", "A", "z", ".", ",", "/", ":", "\n", "\t",
	"é", "\xff", "\x80", "AB12", "12", "00", "DE89", "1111", "9 9", "9-9", "  ", "--",
	"4111111111111111", "44051401359", "DE89370400440532013000",
	"123456789012345678901234567890", "__REDACTED:card-pan__",
}

func randPIIValue(rng *rand.Rand) string {
	var b strings.Builder
	for n := rng.Intn(14); n >= 0; n-- {
		switch rng.Intn(8) {
		case 0:
			b.WriteString(randDigitRun(rng))
		case 1:
			b.WriteString(randSeparatedDigits(rng))
		default:
			b.WriteString(piiFragments[rng.Intn(len(piiFragments))])
		}
	}
	return b.String()
}

func randDigitRun(rng *rand.Rand) string {
	var b strings.Builder
	for n := 1 + rng.Intn(24); n > 0; n-- {
		b.WriteByte(byte('0' + rng.Intn(10)))
	}
	return b.String()
}

// randSeparatedDigits builds card-pan's shape: digits with spaces or dashes between some.
func randSeparatedDigits(rng *rand.Rand) string {
	var b strings.Builder
	for n := 1 + rng.Intn(26); n > 0; n-- {
		b.WriteByte(byte('0' + rng.Intn(10)))
		switch rng.Intn(6) {
		case 0:
			b.WriteByte(' ')
		case 1:
			b.WriteByte('-')
		case 2:
			b.WriteString([]string{"  ", "- ", " -", "--"}[rng.Intn(4)])
		}
	}
	return b.String()
}

// The per-rule cost on prose with no candidate in it, which is what a transcript mostly is.
func BenchmarkPIIRules(b *testing.B) {
	rules := loadedRules(b, PIICore)
	var sb strings.Builder
	for sb.Len() < 1<<20 {
		fmt.Fprintf(&sb, "internal/scrub/packs/pii.go:%d: the scanner walks the value once\n", sb.Len())
	}
	value := sb.String()
	for _, r := range rules {
		b.Run(r.id, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			for i := 0; i < b.N; i++ {
				require.Len(b, r.MatchScanned(value), 0)
			}
		})
	}
}
