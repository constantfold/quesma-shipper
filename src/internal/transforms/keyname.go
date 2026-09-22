package transforms

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// keyNameMatcher redacts a value because of the name attached to it, not its shape (`printenv`
// output has no value shape). It scans exempt fields too; the key name survives.
type keyNameMatcher struct {
	re    *regexp.Regexp
	names []configuredName

	// Lower-cased literal cores ("_token" for *_TOKEN) for the prefilter, nil when one has no sound
	// literal. Accepted: the (?i) regex also folds non-ASCII runes the byte automaton never fires on.
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

// configuredName is uppercased once; suffix marks a leading "*", matched by suffix.
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
		literal, suffix := strings.CutPrefix(n, "*")
		alt := regexp.QuoteMeta(literal)
		if suffix {
			alt = `[A-Za-z0-9_]*` + alt
		}
		alts = append(alts, alt)
		configured[i] = configuredName{upper: strings.ToUpper(literal), suffix: suffix}
		if literal == "" || !isASCII(literal) {
			unfiltered = true
			continue
		}
		stems = append(stems, strings.ToLower(literal))
	}
	if unfiltered || len(stems) == 0 {
		stems = nil
	}
	// NAME=value, NAME: value, NAME = "value"; the value stops at whitespace, quotes and
	// separators so one redaction cannot swallow a whole line.
	pattern := `(?i)\b(?:` + strings.Join(alts, "|") + `)\b\s*[:=]\s*"?([^\s"',;)]+)"?`
	return &keyNameMatcher{re: regexp.MustCompile(pattern), names: configured, stems: stems}
}

// MatchScannedIn ignores the shared PII walk, which holds no candidate shape of this matcher.
func (m *keyNameMatcher) MatchScannedIn(value string, _ *packs.ValueScan) []Span {
	var out []Span
	// The value group is mandatory, so it always participates.
	for _, loc := range m.re.FindAllStringSubmatchIndex(value, -1) {
		out = append(out, Span{Start: loc[2], End: loc[3], RuleID: "key-name"})
	}
	return out
}

// MatchesKeyName reports whether a JSON key names a secret, in which case the whole value goes.
// Field names a program chose (`apiKey`, `x-api-key`) match as words, since `*_API_KEY` compiles
// to `_API_KEY`, which `API_KEY` lacks; configured names match as the environment spells them.
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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func isAlnumByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// secretWords mean "the value is a credential" as the LAST word of a key, not any word:
// `secret_scanning_enabled` is a setting and `token_count` is a number.
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

// keyQualifiers make a trailing "key" a credential: alone it is too common (object_key,
// cache_key), so it counts only when the word before says which kind.
var keyQualifiers = []string{"api", "secret", "private", "access", "signing", "encryption", "auth"}

func matchesSecretKeyName(key string) bool {
	words := splitKeyWords(key)
	if len(words) == 0 {
		return false
	}
	last := words[len(words)-1]

	// The exact word only: input_tokens and max_tokens are counts (TestFieldNamesThatOnlyLookLikeCredentials).
	if secretWords[last] {
		return true
	}
	return last == "key" && len(words) >= 2 && slices.Contains(keyQualifiers, words[len(words)-2])
}

// splitKeyWords lowercases a field name into words split on separators and camelCase humps, a run
// of capitals staying together: `AWSSecretKey` is aws, secret, key. Every predicate is ASCII-only.
func splitKeyWords(key string) []string {
	var buf [8]string // covers a real field name without growing
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
		case isUpper(c) && i > 0 && (isLower(key[i-1]) || isDigit(key[i-1])),
			isUpper(c) && i > 0 && isUpper(key[i-1]) && i+1 < len(key) && isLower(key[i+1]):
			// apiKey -> api | Key; AWSSecret -> AWS | Secret.
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
