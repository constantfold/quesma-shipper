// args.go weighs a transcript tool_use against a store tool call's recorded arguments. Every store
// generation so far changed how arguments are recorded, so each rule names the behaviour that forced it.

package cursorjoin

import (
	"bytes"
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// evidence grades a bubble's recorded arguments against a tool_use; the order is the candidate ranking.
type evidence int

const (
	evidenceNegative evidence = iota // comparable values recorded, none agree
	evidenceWeak                     // only coincidence-length agreement: probably another call's bubble
	evidenceNeutral                  // one side recorded nothing (most current terminal commands): position only
	evidencePartial                  // a value too long to be an accident agrees, another is unaccounted
	evidencePositive                 // every comparable value agrees, at least one substantial
)

// argsEvidence also returns how many values agreed: of two positive bubbles, the one agreeing on more wins.
func argsEvidence(input json.RawMessage, t *toolFormerData) (evidence, int) {
	if len(input) == 0 {
		return evidenceNeutral, 0
	}
	empty := func(s string) bool { return s == "" || s == "{}" || s == "null" }
	stored := strings.TrimSpace(t.RawArgs)
	if empty(stored) {
		stored = strings.TrimSpace(t.Params)
	}
	if empty(stored) {
		return evidenceNeutral, 0
	}

	// Whole values, not substrings: a glob of `**/*` sits inside `**/*.{md,go}`, a directory inside its files.
	var storedAny any
	parsed := json.Unmarshal([]byte(stored), &storedAny) == nil
	storedVals := collectArgValues(storedAny, storedNoiseKeys, nil)
	if parsed && !slices.ContainsFunc(storedVals, func(sv argValue) bool { return !sv.weak }) {
		// Nothing that could confirm a call, as errored calls are recorded; position may speak.
		return evidenceNeutral, 0
	}
	// The store holds what actually ran: its executed form must not score as contradicting the intent.
	strippedStored := ""
	if !parsed {
		strippedStored = stripCursorAttribution(stored)
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		if !parsed && strings.Contains(strippedStored, string(input)) {
			return evidencePositive, 1
		}
		return evidenceNegative, 0
	}

	storedSet := make(map[string]bool, len(storedVals))
	for _, sv := range storedVals {
		storedSet[sv.v] = true
	}
	strongComparable, strongMatched := 0, 0
	long, weakUnaccounted := false, false
	for _, av := range collectArgValues(m, genericArgKeys, nil) {
		if av.weak {
			// Cannot confirm, but can deny; an unparsed record cannot be searched for a short token.
			if parsed && !storedSet[av.v] {
				weakUnaccounted = true
			}
			continue
		}
		strongComparable++
		matches := storedSet[av.v] || slices.ContainsFunc(storedVals, func(sv argValue) bool {
			return !sv.weak && stripCursorAttribution(sv.v) == av.v
		})
		// Unparsed legacy records support only long-value containment, including JSON escapes.
		if !matches && !parsed && len(av.v) >= longArgLen {
			matches = strings.Contains(strippedStored, av.v) || strings.Contains(strippedStored, jsonEscaped(av.v))
		}
		if matches {
			strongMatched++
			long = long || len(av.v) >= longArgLen
		}
	}
	switch {
	case strongComparable == 0:
		return evidenceNeutral, 0
	case strongMatched == strongComparable && !weakUnaccounted:
		// Not a majority: two greps sharing path and glob swapped results. One disagreement vetoes.
		return evidencePositive, strongMatched
	case !parsed && strongMatched > 0:
		// Containment already requires values too long to collide.
		return evidencePositive, strongMatched
	case strongMatched > 0 && long:
		return evidencePartial, strongMatched
	case strongMatched > 0:
		// Not contradiction: edit_file_v2 records only the path; as negative, nine conversations lost bubbles.
		return evidenceWeak, strongMatched
	default:
		return evidenceNegative, 0
	}
}

// What Cursor splices into a command between transcript and store (2026-08-19); the space strips with the flag.
var cursorAttributions = []string{
	` --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>"`,
	"\n\nMade with [Cursor](https://cursor.com)",
}

// stripCursorAttribution also removes the JSON-escaped form, the one inside a stored JSON string.
func stripCursorAttribution(s string) string {
	for _, a := range cursorAttributions {
		s = strings.ReplaceAll(s, a, "")
		if e := jsonEscaped(a); e != a {
			s = strings.ReplaceAll(s, e, "")
		}
	}
	return s
}

// The shortest value that can CONFIRM, and that may match by CONTAINMENT: `*.go` recurs across calls.
const (
	minArgLen  = 4
	longArgLen = 32
)

// argValue is one argument in canonical string form; a weak one can contradict identity, never confirm it.
type argValue struct {
	v    string
	weak bool
}

// collectArgValues walks arguments deterministically; numbers are weak and booleans ignored (flags go unstored).
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

// Stored keys without a transcript counterpart; a shell token of parsingResult let blocks steal bubbles.
var storedNoiseKeys = map[string]bool{"toolCallId": true, "parsingResult": true, "requestedSandboxPolicy": true, "commandDescription": true, "cwd": true}

// Transcript keys whose values recur across unrelated calls.
var genericArgKeys = map[string]bool{"working_directory": true, "cwd": true, "description": true, "explanation": true}

// namesCompatible is for the positional fallbacks only: a mapping this coarse never overrides arguments.
func namesCompatible(display string, t *toolFormerData) bool {
	d, in := normaliseToolName(display), normaliseToolName(cmp.Or(t.Name, string(t.Tool)))
	if d == "" || in == "" || d == in || strings.Contains(in, d) || strings.Contains(d, in) {
		return true
	}
	// MCP: the transcript names the dispatcher, the store the concrete tool. Observed 2026-08-20.
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
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // Encoding a string into a bytes.Buffer cannot fail.
	return buf.String()[1 : buf.Len()-2]
}
