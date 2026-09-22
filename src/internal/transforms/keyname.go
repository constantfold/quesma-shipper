package transforms

import (
	"slices"
	"strings"
)

// Field names (`api_key`, `apiKey`, `x-api-key`) are compared as WORDS: the configured suffix
// `*_API_KEY` compiles to `_API_KEY`, which `API_KEY` does not end with.

// secretWords mark a credential only as the LAST word: `token_count` is a number.
var secretWords = map[string]bool{
	"password":    true,
	"passwd":      true,
	"pwd":         true,
	"secret":      true,
	"token":       true,
	"apikey":      true,
	"credential":  true,
	"credentials": true,
	"auth":        true,
	// A logged request header is the most common way a credential reaches a transcript.
	"authorization": true,
	"cookie":        true,
	// "session" is deliberately absent: alone it is an id, not a credential.
}

// keyQualifiers make a trailing "key" a credential; alone it is too common (object_key, cache_key).
var keyQualifiers = []string{"api", "secret", "private", "access", "signing", "encryption", "auth"}

func matchesSecretKeyName(key string) bool {
	words := splitKeyWords(key)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]

	// The exact word only: input_tokens is a count (TestFieldNamesThatOnlyLookLikeCredentials).
	if secretWords[last] {
		return true
	}
	return last == "key" && len(words) >= 2 && slices.Contains(keyQualifiers, words[len(words)-2])
}

// splitKeyWords keeps a run of capitals together (`AWSSecretKey` is aws, secret, key). Bytes, not
// runes: every predicate is ASCII-only, so a continuation byte breaks nothing.
func splitKeyWords(key string) []string {
	var buf [8]string
	words := buf[:0]
	start := -1

	flush := func(end int) {
		if start >= 0 {
			words = append(words, strings.ToLower(key[start:end]))
			start = -1
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '_' || c == '-' || c == '.' || c == ' ' || c == ':' || c == '/':
			flush(i)
		case isUpper(c) && i > 0 && (isLower(key[i-1]) || isDigit(key[i-1])):
			// apiKey -> api | Key
			flush(i)
			start = i
		case isUpper(c) && i > 0 && isUpper(key[i-1]) &&
			i+1 < len(key) && isLower(key[i+1]):
			// AWSSecret -> AWS | Secret
			flush(i)
			start = i
		default:
			if start < 0 {
				start = i
			}
		}
	}
	flush(len(key))
	return words
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
