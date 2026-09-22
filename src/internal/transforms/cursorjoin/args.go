// args.go weighs a transcript tool_use against a store tool call's recorded arguments. The
// join's most drift-exposed surface: every store generation so far has changed how arguments are
// recorded, so each rule names the observed behaviour that forced it.

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

// evidence is what a tool bubble's recorded arguments say about a transcript tool_use. The
// order is the candidate ranking: when no bubble's arguments agree in full, matchBlock takes
// the highest grade in reach before falling back to position.
type evidence int

const (
	// The two sides recorded comparable values and none of them agree.
	evidenceNegative evidence = iota
	// Some values agree, none long enough to rule out coincidence. Ranks below an empty record: a
	// bubble whose values half-belong to another call is probably that call's.
	evidenceWeak
	// One side recorded nothing, as current stores do for most terminal commands; position only.
	evidenceNeutral
	// A value too long to be an accident agrees while another goes unaccounted: store variants.
	evidencePartial
	// Every comparable value agrees, at least one of them substantial.
	evidencePositive
)

// argsEvidence weighs a transcript tool_use against a store tool call's recorded arguments.
// Alongside the grade it returns the strength — how many values agreed — because two bubbles can
// both grade positive and the one agreeing on more of the call is the call.
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

	// Whole value against whole value, not against the stored text: the sides name arguments
	// differently (glob_pattern/globPattern), and substring evidence matches unrelated calls — a
	// glob of `**/*` sits inside `**/*.{md,go}`, a directory inside every path under it.
	var storedAny any
	parsed := json.Unmarshal([]byte(stored), &storedAny) == nil
	storedVals := collectArgValues(storedAny, storedNoiseKeys, nil)
	if parsed && !slices.ContainsFunc(storedVals, func(sv argValue) bool { return !sv.weak }) {
		// Nothing that could confirm a call, as errored calls are recorded; position may speak.
		return evidenceNeutral, 0
	}
	// The transcript holds the model's intent, the store what actually ran: an executed form
	// scoring as contradiction would bar the call's own bubble.
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
		// Agreement on everything, not a majority: two greps sharing path and glob but not
		// pattern swapped each other's results. One disagreeing value, however short, vetoes.
		return evidencePositive, strongMatched
	case !parsed && strongMatched > 0:
		// Containment already requires values too long to collide.
		return evidencePositive, strongMatched
	case strongMatched > 0 && long:
		return evidencePartial, strongMatched
	case strongMatched > 0:
		// Not contradiction: the store records variants the transcript does not — edit_file_v2
		// records the path and never the strings. Scored negative, nine real conversations lost
		// their own bubbles.
		return evidenceWeak, strongMatched
	default:
		return evidenceNegative, 0
	}
}

// The fragments Cursor splices into a command between the transcript's record and the store's,
// observed live 2026-08-19. The literals are the vendor's, so their drift lands as a mismatch
// alarm. The trailer carries its leading space so it strips wherever the flag sits.
var cursorAttributions = []string{
	` --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>"`,
	"\n\nMade with [Cursor](https://cursor.com)",
}

// stripCursorAttribution removes the splices in both the plain and the JSON-escaped form: inside
// a stored blob holding JSON as a string, the plain literal never occurs.
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

// argValue is one comparable argument value in canonical string form; weak marks the ones that
// can contradict identity but never confirm it.
type argValue struct {
	v    string
	weak bool
}

// collectArgValues walks either side's decoded arguments, at any depth, in a deterministic order.
// Numbers are weak like short strings — offsets recur across unrelated calls — and booleans are no
// evidence at all: a flag the store never records demoted the true bubble on most terminal calls.
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

// Stored keys without a transcript counterpart. parsingResult is a parse tree of the terminal
// command, and any shell token of it let an unrelated block steal the terminal bubble.
var storedNoiseKeys = map[string]bool{
	"toolCallId":             true,
	"parsingResult":          true,
	"requestedSandboxPolicy": true,
	"commandDescription":     true,
	"cwd":                    true,
}

// Transcript keys whose values recur across unrelated calls.
var genericArgKeys = map[string]bool{
	"working_directory": true,
	"cwd":               true,
	"description":       true,
	"explanation":       true,
}

// namesCompatible reports whether a display name and a store internal name plausibly denote the
// same tool. Only for the positional fallbacks: a mapping this coarse never overrides arguments.
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
