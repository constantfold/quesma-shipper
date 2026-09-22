package packs

// One classification walk for the keywordless PII rules (card-pan, iban, pesel), returning exactly
// their regexes' spans in order; pii_test.go replays the regexes. Go's \b is ASCII-only, a byte test.

// One bit per class, so a run's classes accumulate with an AND.
const (
	piiWord  = 1 << iota // [0-9A-Za-z_], Go's \w
	piiDigit             // [0-9]
	piiUpper             // [0-9A-Z], the IBAN body alphabet
	piiAlpha             // [A-Z], the IBAN country prefix
)

// piiClass gives a byte >= 0x80 class 0: non-word however it decodes, and unconsumable.
var piiClass = func() (t [256]uint8) {
	for c := 0; c < 256; c++ {
		switch {
		case c >= '0' && c <= '9':
			t[c] = piiWord | piiDigit | piiUpper
		case c >= 'A' && c <= 'Z':
			t[c] = piiWord | piiUpper | piiAlpha
		case c >= 'a' && c <= 'z', c == '_':
			t[c] = piiWord
		}
	}
	return t
}()

// isWordByte reports Go's ASCII \w, the whole of what \b looks at.
func isWordByte(c byte) bool { return piiClass[c]&piiWord != 0 }

// The card-pan pattern's bounds: 12 to 18 repetitions, so 13 to 19 digits.
const panMaxDigits, panMinReps = 19, 12

type fusedKind uint8

const (
	fusedNone fusedKind = iota
	fusedPESEL
	fusedIBAN
	fusedCardPAN
)

// ValueScan is the per-value scratch the fused walk fills; the caller owns one per Scrub call.
type ValueScan struct {
	value string
	done  bool
	lists [fusedCardPAN + 1][]Span // candidates by fusedKind
}

// Reset points the scan at a new value; the walk waits until a rule asks.
func (c *ValueScan) Reset(value string) { c.value, c.done = value, false }

// candidates walks the value on the first ask. The slice aliases the scan's storage until the next Reset.
func (c *ValueScan) candidates(kind fusedKind) []Span {
	if !c.done {
		c.walk()
		c.done = true
	}
	return c.lists[kind]
}

// walk fills all lists in one pass over \w runs: PESEL 11 digits, IBAN 15-34 shaped AANN, card-pan digit-led.
func (c *ValueScan) walk() {
	for k := range c.lists {
		c.lists[k] = c.lists[k][:0]
	}

	value := c.value
	// panCursor reproduces FindAll's non-overlap for card-pan: a match consumes its bytes.
	panCursor := 0

	for i := 0; i < len(value); {
		first := piiClass[value[i]]
		if first&piiWord == 0 {
			i++
			continue
		}
		start := i
		acc := first
		for i++; i < len(value); i++ {
			cl := piiClass[value[i]]
			if cl&piiWord == 0 {
				break
			}
			acc &= cl
		}
		n := i - start

		if acc&piiDigit != 0 && n == 11 {
			c.lists[fusedPESEL] = append(c.lists[fusedPESEL], Span{Start: start, End: i})
		}
		if acc&piiUpper != 0 && n >= 15 && n <= 34 &&
			first&piiAlpha != 0 &&
			piiClass[value[start+1]]&piiAlpha != 0 &&
			piiClass[value[start+2]]&piiDigit != 0 &&
			piiClass[value[start+3]]&piiDigit != 0 {
			c.lists[fusedIBAN] = append(c.lists[fusedIBAN], Span{Start: start, End: i})
		}
		if first&piiDigit != 0 && start >= panCursor {
			if end, ok := scanCardPANFrom(value, start); ok {
				c.lists[fusedCardPAN] = append(c.lists[fusedCardPAN], Span{Start: start, End: end})
				panCursor = end
			}
		}
	}
}

// scanCardPANFrom ends `\b(?:[0-9][ -]?){12,18}[0-9]\b` from a \b digit: greedy, the first count ending on \b.
func scanCardPANFrom(value string, start int) (int, bool) {
	var chain [panMaxDigits]int
	n := 0
	for p := start; ; {
		chain[n] = p
		n++
		if n == panMaxDigits {
			break
		}
		if p+1 < len(value) && piiClass[value[p+1]]&piiDigit != 0 {
			p++
			continue
		}
		if p+2 < len(value) && (value[p+1] == ' ' || value[p+1] == '-') &&
			piiClass[value[p+2]]&piiDigit != 0 {
			p += 2
			continue
		}
		break
	}
	for reps := n - 1; reps >= panMinReps; reps-- {
		end := chain[reps] + 1
		if end < len(value) && piiClass[value[end]]&piiWord != 0 {
			continue
		}
		return end, true
	}
	return 0, false
}
