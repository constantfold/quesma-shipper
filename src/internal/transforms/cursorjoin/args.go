// args.go weighs a transcript tool_use against a store call's recorded arguments. Every store
// generation so far has changed how arguments are recorded, so each rule names the behaviour behind it.

package cursorjoin

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// evidence is ordered as matchBlock ranks candidates before falling back to position.
type evidence int

const (
	// The two sides recorded comparable values and none of them agree.
	evidenceNegative evidence = iota
	// Some values agree, none long enough to rule out coincidence (same-tree searches share the path).
	// Ranks below an empty record: values half-belonging to another call suggest it is that call's.
	evidenceWeak
	// Nothing to confirm or deny (rawArgs "{}", empty params on most terminal commands); position only.
	evidenceNeutral
	// A long whole value agrees while another goes unaccounted: the store recorded variants.
	evidencePartial
	// Every comparable value agrees, at least one of them substantial.
	evidencePositive
)

// argsEvidence also returns how many values agreed: the positive agreeing on more is the call.
func argsEvidence(input json.RawMessage, t *toolFormerData) (evidence, int) {
	if len(input) == 0 {
		return evidenceNeutral, 0
	}
	stored := strings.TrimSpace(t.RawArgs)
	if stored == "" || stored == "{}" || stored == "null" {
		stored = strings.TrimSpace(t.Params)
	}
	if stored == "" || stored == "{}" || stored == "null" {
		return evidenceNeutral, 0
	}

	// Whole parsed values, not substrings of the stored text: keys differ (glob_pattern/globPattern)
	// so cannot be paired, and substrings match unrelated calls (`**/*` inside `**/*.{md,go}`).
	storedVals, parsed := argValues(stored)
	if parsed && !slices.ContainsFunc(storedVals, func(sv argValue) bool { return !sv.weak }) {
		// Nothing that could confirm a call, as errored calls are recorded; position may still speak.
		return evidenceNeutral, 0
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		// The input is not an object; containment is all that is left.
		if !parsed && strings.Contains(stripCursorAttribution(stored), string(input)) {
			return evidencePositive, 1
		}
		return evidenceNegative, 0
	}

	storedSet := make(map[string]bool, len(storedVals))
	for _, sv := range storedVals {
		storedSet[sv.v] = true
	}
	// The store holds what ran, the transcript the intent: attribution must not bar the call's bubble.
	strippedStored := ""
	if !parsed {
		strippedStored = stripCursorAttribution(stored)
	}

	strongComparable, strongMatched := 0, 0
	long := false
	weakUnaccounted := false
	for _, av := range collectArgValues(m, genericArgKeys, nil) {
		if av.weak {
			// Too short to confirm, but separates two calls when it DISAGREES. Parsed
			// records only: an unparsed one cannot be safely searched for a short token.
			if parsed && !storedSet[av.v] {
				weakUnaccounted = true
			}
			continue
		}
		strongComparable++
		if storedSet[av.v] {
			strongMatched++
			long = long || len(av.v) >= longArgLen
			continue
		}
		if slices.ContainsFunc(storedVals, func(sv argValue) bool {
			return !sv.weak && stripCursorAttribution(sv.v) == av.v
		}) {
			strongMatched++
			long = long || len(av.v) >= longArgLen
			continue
		}
		if !parsed && len(av.v) >= longArgLen {
			// Older generations wrote a bare string: containment only, for values too long to
			// collide, and also escaped, since a string field holding JSON escapes quotes and newlines.
			if strings.Contains(strippedStored, av.v) {
				strongMatched++
				long = true
				continue
			}
			if e := jsonEscaped(av.v); e != av.v && strings.Contains(strippedStored, e) {
				strongMatched++
				long = true
				continue
			}
		}
	}
	switch {
	case strongComparable == 0:
		return evidenceNeutral, 0
	case strongMatched == strongComparable && !weakUnaccounted:
		// Identity needs everything, not a majority: two greps sharing path and glob but not pattern
		// swapped results with no alarm. One disagreeing value, however short, vetoes.
		return evidencePositive, strongMatched
	case !parsed && strongMatched > 0:
		// Containment already requires values too long to collide.
		return evidencePositive, strongMatched
	case strongMatched > 0 && long:
		return evidencePartial, strongMatched
	case strongMatched > 0:
		// Not contradiction: a true bubble often matches a strict subset (edit_file_v2 records
		// the path, never the strings). Scoring them negative barred nine real conversations' bubbles.
		return evidenceWeak, strongMatched
	default:
		return evidenceNegative, 0
	}
}

// Fragments Cursor splices into commands between transcript and store (observed 2026-08-19); drift
// lands as a mismatch alarm. The trailer carries its leading space so it strips wherever it sits.
var cursorAttributions = []string{
	` --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>"`,
	"\n\nMade with [Cursor](https://cursor.com)",
}

// Also JSON-escaped: inside a stored blob holding JSON as a string, the plain literal never occurs.
func stripCursorAttribution(s string) string {
	for _, a := range cursorAttributions {
		s = strings.ReplaceAll(s, a, "")
		if e := jsonEscaped(a); e != a {
			s = strings.ReplaceAll(s, e, "")
		}
	}
	return s
}

// minArgLen is the shortest value that can CONFIRM anything, longArgLen the shortest a
// CONTAINMENT match may: `**/*`, `*.go` and `-la` are arguments of a hundred unrelated calls.
const (
	minArgLen  = 4
	longArgLen = 32
)

// argValue is a comparable value in canonical form; a weak one can contradict identity, never confirm.
type argValue struct {
	v    string
	weak bool
}

// argValues reports false when the blob does not parse, leaving the caller only the raw text.
func argValues(stored string) ([]argValue, bool) {
	var v any
	if err := json.Unmarshal([]byte(stored), &v); err != nil {
		return nil, false
	}
	return collectArgValues(v, storedNoiseKeys, nil), true
}

// Both sides take this walk, in deterministic order. Numbers are weak (offsets and limits recur),
// booleans no evidence: a flag the store never records demoted the true bubble on most terminal calls.
func collectArgValues(v any, skip map[string]bool, out []argValue) []argValue {
	switch t := v.(type) {
	case string:
		if t != "" {
			out = append(out, argValue{v: t, weak: len(t) < minArgLen})
		}
	case float64:
		out = append(out, argValue{v: strconv.FormatFloat(t, 'g', -1, 64), weak: true})
	case []any:
		for _, e := range t {
			out = collectArgValues(e, skip, out)
		}
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(t)) {
			if skip[k] {
				continue
			}
			out = collectArgValues(t[k], skip, out)
		}
	}
	return out
}

// Stored keys with no transcript counterpart, matching only by accident. parsingResult holds every
// shell token plus the workspace root, and any fragment let an unrelated block steal the bubble.
var storedNoiseKeys = map[string]bool{
	"toolCallId":             true,
	"parsingResult":          true,
	"requestedSandboxPolicy": true,
	"commandDescription":     true,
	"cwd":                    true,
}

// Transcript input keys whose values recur across unrelated calls, so cannot discriminate.
var genericArgKeys = map[string]bool{
	"working_directory": true,
	"cwd":               true,
	"description":       true,
	"explanation":       true,
}

// namesCompatible serves positional fallbacks only: a mapping this coarse must never override arguments.
func namesCompatible(display string, t *toolFormerData) bool {
	internal := cmp.Or(t.Name, string(t.Tool))
	if display == "" || internal == "" {
		return true // nothing to compare; position stands
	}
	d := normaliseToolName(display)
	in := normaliseToolName(internal)
	if d == "" || in == "" || d == in || strings.Contains(in, d) || strings.Contains(d, in) {
		return true
	}
	// MCP calls: the transcript names the generic dispatcher, the store the concrete tool it
	// routed to, so the substring rule never relates the two. Observed live 2026-08-20.
	if d == "callmcptool" && strings.HasPrefix(in, "mcp") {
		return true
	}
	return slices.Contains(toolNamePairs[d], in)
}

// toolNamePairs are the display names whose internal name shares no substring with them.
var toolNamePairs = map[string][]string{
	"shell":      {"runterminalcommandv2", "runterminalcmd"},
	"strreplace": {"editfilev2", "searchreplace"},
	"write":      {"editfilev2", "writefile", "createfilev2"},
}

func normaliseToolName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, strings.ToLower(s))
}

// jsonEscaped is the string as it appears inside a JSON document, without the quotes.
func jsonEscaped(s string) string {
	b, err := marshalCompact(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}
