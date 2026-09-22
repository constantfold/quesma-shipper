package packs

import "strings"

// Hand scanner for the email rule, whose keyword "@" fires on nearly every value. It reproduces
// the corpus pattern's leftmost-first semantics; pii_test.go replays both, so a corpus edit
// cannot leave the scanner behind.

// The email pattern's character classes plus \w for \b, which is ASCII-only, so a byte test answers it.
const (
	clsLocal  = 1 << 0 // [A-Za-z0-9._%+-], the local part
	clsDomain = 1 << 1 // [A-Za-z0-9.-], the domain
	clsWord   = 1 << 2 // [0-9A-Za-z_], for \b
	clsAlpha  = 1 << 3 // [A-Za-z], the TLD
)

var emailClass = func() (t [256]uint8) {
	for c := 0; c < 256; c++ {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			t[c] = clsLocal | clsDomain | clsWord | clsAlpha
		case c >= '0' && c <= '9':
			t[c] = clsLocal | clsDomain | clsWord
		case c == '.', c == '-':
			t[c] = clsLocal | clsDomain
		case c == '_':
			t[c] = clsLocal | clsWord
		case c == '%', c == '+':
			t[c] = clsLocal
		}
	}
	return t
}()

// scanEmail anchors on the '@' signs. The local run ends exactly at one, so leftmost is the first
// position in it where \b holds; the domain split is the last '.' that works, and the TLD can only be
// the whole letter run.
func scanEmail(value string) []Span {
	var out []Span
	// from is where FindAll would resume; at is the '@' cursor, which also passes failed candidates.
	from, at := 0, 0
	for {
		rel := strings.IndexByte(value[at:], '@')
		if rel < 0 {
			return out
		}
		sign := at + rel
		at = sign + 1

		// Back to the start of the local-part run, never earlier than from.
		p := sign
		for p > from && emailClass[value[p-1]]&clsLocal != 0 {
			p--
		}
		// Leftmost start in [p, sign) where \b holds, which reads the real byte before p.
		start := -1
		for i := p; i < sign; i++ {
			prevWord := i > 0 && emailClass[value[i-1]]&clsWord != 0
			if prevWord != (emailClass[value[i]]&clsWord != 0) {
				start = i
				break
			}
		}
		if start < 0 {
			continue
		}

		// The last usable '.' needs a domain byte before, a two-letter TLD after, and \b closing it.
		lo := sign + 1
		hi := lo
		for hi < len(value) && emailClass[value[hi]]&clsDomain != 0 {
			hi++
		}
		end := -1
		for dot := hi - 1; dot > lo; dot-- {
			if value[dot] != '.' {
				continue
			}
			tld := dot + 1
			for tld < hi && emailClass[value[tld]]&clsAlpha != 0 {
				tld++
			}
			if tld-dot-1 < 2 {
				continue
			}
			if tld < len(value) && emailClass[value[tld]]&clsWord != 0 {
				continue
			}
			end = tld
			break
		}
		if end < 0 {
			continue
		}

		out = append(out, Span{Start: start, End: end})
		from, at = end, end
	}
}
