package transforms

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// keyNameMatcher redacts a value because of the name attached to it, not its shape (`printenv`
// output has no value shape). It scans exempt fields too; the key name survives.
type keyNameMatcher struct {
	re    *regexp.Regexp
	names []configuredName

	// Lower-cased literal cores of the alternation ("_token" for *_TOKEN) for the prefilter. That
	// narrows the (?i) regex, which also folds non-ASCII runes (long s, Kelvin sign) the byte
	// automaton never fires on; accepted. nil means no sound literal, so the regex always runs.
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

func (m *keyNameMatcher) RuleID() string { return "key-name" }

// MatchScannedIn ignores the shared PII walk, which holds no candidate shape of this matcher.
func (m *keyNameMatcher) MatchScannedIn(value string, _ *packs.ValueScan) []Span {
	var out []Span
	// The value group is mandatory, so it always participates.
	for _, loc := range m.re.FindAllStringSubmatchIndex(value, -1) {
		out = append(out, Span{Start: loc[2], End: loc[3], RuleID: m.RuleID()})
	}
	return out
}

// MatchesKeyName reports whether a JSON key itself names a secret, in which case the whole value
// goes. Author-spelled field names match as words, configured names as the environment spells them.
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
