package transforms

import (
	"regexp"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

// keyNameMatcher redacts a value because of the name attached to it, not its shape
// (`printenv` output has no recognisable value shape). It scans exempt fields too, since a
// secret named AWS_SECRET_ACCESS_KEY is one wherever it appears; the key name survives.
type keyNameMatcher struct {
	re *regexp.Regexp

	// Each configured name uppercased once, so MatchesKeyName folds only the key it is
	// given; suffix marks a name configured with a leading "*", matched by suffix.
	names []configuredName

	// Lower-cased literal cores of the alternation ("_token" for *_TOKEN). Gating re behind the
	// shared automaton narrows the rule: re is (?i), which also folds non-ASCII runes (long s,
	// Kelvin sign) the byte automaton can never fire on. Accepted; nil stems mean no sound
	// literal, so the regex runs ungated.
	stems []string
}

// DefaultSecretKeyNames is the starting set; config additions only make scrubbing
// stricter.
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
	// NAME=value, NAME: value, NAME = "value"; the value run stops at whitespace,
	// quotes and separators so one redaction cannot swallow a whole line.
	pattern := `(?i)\b(?:` + strings.Join(alts, "|") + `)\b\s*[:=]\s*"?([^\s"',;)]+)"?`
	return &keyNameMatcher{re: regexp.MustCompile(pattern), names: configured, stems: stems}
}

func (m *keyNameMatcher) RuleID() string { return "key-name" }

// MatchScannedIn ignores the shared PII walk: this matcher has no candidate shape in it
// to collect.
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

// MatchesKeyName reports whether a JSON key itself names a secret, in which case the
// whole value goes. Two vocabularies: configured names match as the environment spells
// them, author-spelled field names match as words (matchesSecretKeyName in keyname.go).
func (m *keyNameMatcher) MatchesKeyName(key string) bool {
	if key == "" {
		return false
	}
	if matchesSecretKeyName(key) {
		return true
	}
	// Configured environment names apply as written to field names too.
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
