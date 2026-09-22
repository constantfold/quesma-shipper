package packs

import (
	"slices"
	"strings"
)

// Checksum-verified matchers exist because their shapes are otherwise far too common: eleven digits
// is an id, eleven with a valid PESEL check digit an identity number. Everything else favours recall.

func digitsOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// luhnValid is the payment card Luhn check; d must be digits only.
func luhnValid(d string) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// panValid checks grouping, PAN length and issuer range before Luhn, which alone passes one run in ten.
func panValid(s string) bool {
	groups := []int{0}
	sep := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			groups[len(groups)-1]++
			continue
		}
		if sep == 0 {
			sep = c
		} else if c != sep {
			return false // mixed separators: nobody writes a card that way
		}
		groups = append(groups, 0)
	}

	// Card groupings: 4-4-4-4, amex 4-6-5, and 4-4-4-4-3.
	if len(groups) > 1 && !slices.Equal(groups, []int{4, 4, 4, 4}) && !slices.Equal(groups, []int{4, 6, 5}) &&
		!slices.Equal(groups, []int{4, 4, 4, 4, 3}) {
		return false
	}

	d := digitsOnly(s)
	switch len(d) {
	case 13, 14, 15, 16, 19:
	default:
		return false
	}

	switch d[0] {
	case '4', '5', '6':
	case '3':
		switch d[1] {
		case '0', '4', '6', '7', '8':
		default:
			return false
		}
	case '2':
		iin := int(d[0]-'0')*1000 + int(d[1]-'0')*100 + int(d[2]-'0')*10 + int(d[3]-'0')
		if iin < 2221 || iin > 2720 {
			return false
		}
	default:
		return false
	}

	return luhnValid(d)
}

// peselValid implements the Polish national identity number check digit.
func peselValid(s string) bool {
	d := digitsOnly(s)
	if len(d) != 11 {
		return false
	}
	weights := [10]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := range 10 {
		sum += weights[i] * int(d[i]-'0')
	}
	check := (10 - sum%10) % 10
	if check != int(d[10]-'0') {
		return false
	}
	// A PESEL encodes a birth date, so an impossible month keeps the rule off numeric ids.
	month := int(d[2]-'0')*10 + int(d[3]-'0')
	switch {
	case month >= 1 && month <= 12, // 1900s
		month >= 21 && month <= 32, // 2000s
		month >= 41 && month <= 52, // 2100s
		month >= 61 && month <= 72, // 2200s
		month >= 81 && month <= 92: // 1800s
		return true
	}
	return false
}

// ibanValid implements the ISO 13616 mod-97 check.
func ibanValid(s string) bool {
	v := strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(v) < 15 || len(v) > 34 {
		return false
	}
	// The first four characters move to the end, letters count as 10-35, and mod 97 streams.
	rearranged := v[4:] + v[:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}
