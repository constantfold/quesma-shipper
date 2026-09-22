package packs

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The scanners claim to return exactly what their regex returned, so both paths are replayed
// over input built to break the scanner, raw candidates compared as well as the checksummed
// result, so a divergence the checksum happens to mask still fails.

// piiScannerRules returns the loaded rules that carry a hand scanner.
func piiScannerRules(t *testing.T) []*Rule {
	t.Helper()
	var out []*Rule
	for _, r := range loadedRules(t, PIICore) {
		if r.hand != nil || r.fused != fusedNone {
			out = append(out, r)
		}
	}
	// The three keywordless shapes plus email, whose gate fires on nearly every value.
	if len(out) != 4 {
		t.Fatalf("expected four pii-core rules to carry scanners, got %d", len(out))
	}
	return out
}

// scanCandidates is the rule's byte walk before guard and checksum: its slot in the shared
// walk, or its own scanner.
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
	var want [][]int
	for _, loc := range r.re.FindAllStringIndex(value, -1) {
		want = append(want, loc)
	}
	var got [][]int
	for _, s := range scanCandidates(r, value) {
		got = append(got, []int{s.Start, s.End})
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s candidates on %q: regex %v, scanner %v", r.id, value, want, got)
	}

	// Then the rule's answer, checksum and rule id included.
	if w, g := r.matchSweep(value), r.MatchScanned(value); !reflect.DeepEqual(w, g) {
		t.Fatalf("%s spans on %q: regex %v, scanner %v", r.id, value, w, g)
	}
}

// The cases the fuzz below would only reach by luck: candidates touching both ends of the
// value, every separator position, runs one byte either side of every bound.
var piiEdgeValues = []string{
	"", " ", "-", "0", "_", "abc", "\xff", "é", "\x80\x80\x80",
	"12345678901", " 12345678901 ", "12345678901x", "x12345678901",
	"_12345678901", "12345678901_", "123456789012", "1234567890",
	"12345678901 12345678901", "12345678901-12345678901",
	"44051401359", " 44051401359", "44051401359\n", "4405140135944051401359",
	"4111111111111111", " 4111111111111111 ", "4111 1111 1111 1111",
	"4111-1111-1111-1111", "4111 1111-1111 1111", "4111  1111 1111 1111",
	"-4111111111111111-", "x4111111111111111", "4111111111111111x",
	"41111111111111111111", "411111111111111111111111111111",
	"1 2 3 4 5 6 7 8 9 0 1 2 3", "1-2-3-4-5-6-7-8-9-0-1-2-3",
	"1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3",
	"4111111111111111 4111111111111111", "0000000000000000",
	"411111111111111 1", "411111111111111-", "-411111111111111",
	"4111111111111111-1", "1-4111111111111111", "4111111111111111 1111",
	"DE89370400440532013000", " DE89370400440532013000 ",
	"DE893704004405320130001111111111111", "GB82WEST12345698765432",
	"de89370400440532013000", "DE8937040044053201300", "XX00XXXXXXXXXXX",
	"DE89370400440532013000_", "_DE89370400440532013000",
	"DE89 3704 0044 0532 0130 00", "AB12CDEFGHIJKLMNO",
	"AB12CDEFGHIJKLM", "AB12CDEFGHIJKL", "A1B2CDEFGHIJKLMNO",
	"12ABCDEFGHIJKLMNO", "AB1CDEFGHIJKLMNOP",
	strings.Repeat("9", 40), strings.Repeat("9 ", 40), strings.Repeat("9-", 40),
	strings.Repeat("A9", 40), strings.Repeat("1", 19) + "é" + strings.Repeat("1", 19),
	// Mixed shapes in one value, for the shared walk.
	"44051401359 44051401359", "DE8937040044053201300044051401359",
	"4111 1111 1111 1111 44051401359 4111111111111111",
	"44051401359-4111 1111 1111 1111-DE89370400440532013000",
	"AB12CDEFGHIJKLMN", "AB12CDEFGHIJKLMNo", "AB12CDEFGHIJKLMN_",
	strings.Repeat("4111", 20), strings.Repeat("1 ", 200),
}

// The edges, then the volume half: digit soup with separators everywhere, valid and invalid checksums.
func TestPIIScannersAgreeWithTheirRegex(t *testing.T) {
	rules := piiScannerRules(t)

	values := slices.Clone(piiEdgeValues)
	rng := rand.New(rand.NewSource(20260816))
	for i := 0; i < 40000; i++ {
		values = append(values, randPIIValue(rng))
	}
	for _, r := range rules {
		for _, v := range values {
			compareScannerAndRegex(t, r, v)
		}
	}
}

// The one combination that would redact a different span than the pattern must not compile.
func TestPIIScannerRejectsACaptureGroup(t *testing.T) {
	spec := ruleSpec{ID: "x", Regex: `\b[0-9]{11}\b`, Scanner: "pesel", Capture: 1}
	if _, err := compileSpec("test", spec); err == nil {
		t.Fatal("a scanner paired with a capture group must not compile")
	}
	spec.Scanner = "nope"
	spec.Capture = 0
	if _, err := compileSpec("test", spec); err == nil {
		t.Fatal("an unknown scanner must not compile")
	}
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
				if got := r.MatchScanned(value); len(got) != 0 {
					b.Fatalf("expected no match, got %d", len(got))
				}
			}
		})
	}
}
