package cursorjoin_test

import (
	"fmt"
	"testing"
)

const (
	etagArgs  = `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`
	purgeArgs = `{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}`
)

// A repeat is a transcript call the store recorded once. It attaches nothing and consumes nothing,
// so it must neither hide a hole nor take a bubble that is some other call's.
func TestRepeatedCalls(t *testing.T) {
	var farBack []string
	var farBackRows []storeRow
	for i := range 64 {
		args := fmt.Sprintf(`{"pattern":"sym%02dAlpha|sym%02dBeta","path":"/work/api/pkg%02d"}`, i, i, i)
		farBack = append(farBack, turn(use("Grep", args)))
		farBackRows = append(farBackRows, toolRow(fmt.Sprintf("fill%02d", i), "ripgrep_raw_search", args, "pkg.go:1"))
	}
	var subagent []storeRow
	for i := range 20 {
		subagent = append(subagent, toolRow(fmt.Sprintf("sub%02d", i), "read_file_v2", fmt.Sprintf(`{"path":"/work/api/sub/f%02d.go"}`, i), "subagent detail"))
	}
	const resolve = `{"path":"/work/api/internal/config/resolve.go"}`

	runJoinCases(t, []joinCase{{
		// The same evidence fits a store that recorded both runs, the second argument-less, so the
		// re-run ships undecided and the argument-less bubble stays barred from later fallbacks.
		name:       "a call the store recorded once is not a mismatch",
		query:      "look twice",
		transcript: jsonl(turn(use("Grep", etagArgs)), turn(use("Grep", etagArgs)), turn(use("Grep", purgeArgs)), turn(text("Both live in etag.go."))),
		bubbles: []storeRow{
			toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9"),
			toolRow("argless", "ripgrep_raw_search", `{}`, "NOT THE REPEAT'S RESULT"),
			toolRow("purge", "ripgrep_raw_search", purgeArgs, "purge.go:14"),
			said("a1", "Both live in etag.go."),
		},
		want:   map[int][]string{1: {"grep"}, 2: {}, 3: {"purge"}, 4: {"a1"}},
		absent: []string{"NOT THE REPEAT'S RESULT"},
	}, {
		// The repeat consumes nothing, so the next consuming match is what catches the hole.
		name:  "a hole before a repeat is a mismatch, not tail",
		query: "look around",
		transcript: jsonl(turn(use("Grep", etagArgs)), turn(use("Grep", `{"pattern":"nothing|the|store|knows","path":"/work/api/internal/engine"}`)),
			turn(use("Grep", etagArgs)), turn(use("Grep", purgeArgs))),
		bubbles:  []storeRow{toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9"), toolRow("purge", "ripgrep_raw_search", purgeArgs, "purge.go:14")},
		mismatch: true,
	}, {
		// Only an identity-grade consumer makes a later agreeing call a repeat: here the first search
		// reaches the second's bubble by position, and a repeat would ship it wearing the wrong result.
		name:       "a fallback consumer does not make the next call a repeat",
		query:      "scan the backends",
		transcript: jsonl(turn(use("Grep", `{"pattern":"PurgePrefix|opts","path":"/work/s3"}`)), turn(use("Grep", `{"pattern":"quoteETag|normaliseETag","path":"/work/s3"}`)), turn(text("Both live in etag.go."))),
		bubbles:    []storeRow{toolRow("etag", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/s3"}`, "etag.go:9"), said("a1", "Both live in etag.go.")},
		mismatch:   true,
	}, {
		// Left unconsumed, the undecided bubble became the next terminal command's positional fallback.
		name:       "an undecidable repeat attaches nothing and does not cascade",
		query:      "run the tests",
		transcript: jsonl(turn(use("Shell", `{"command":"npm test"}`)), turn(use("Shell", `{"command":"npm test"}`)), turn(use("Shell", `{"command":"git status --short"}`))),
		bubbles: []storeRow{
			toolRow("t1", "run_terminal_command_v2", `{"command":"npm test"}`, "FAIL: 3 failing"),
			toolRow("t2", "run_terminal_command_v2", `{}`, "PASS all tests passed"),
			toolRow("t3", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go"),
		},
		want:   map[int][]string{2: {}, 3: {"t3"}},
		absent: []string{"PASS all tests passed"},
	}, {
		// Repeat detection is not bounded by the look-behind window: it consumes nothing, so the
		// misplacement the window guards against cannot happen. 64 consumed calls sit in between.
		name:       "a store-deduped re-run far back is still a repeat",
		query:      "audit everything",
		transcript: jsonl(append(append([]string{turn(use("Grep", etagArgs))}, farBack...), turn(use("Grep", etagArgs)), turn(text("All checks passed.")))...),
		bubbles:    append(append([]storeRow{toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9")}, farBackRows...), said("a1", "All checks passed.")),
		infos:      []string{"repeat"},
	}, {
		// A repeat verdict surveys the whole store: the re-run's own bubble exists past the forward
		// window, behind store-only subagent bubbles, so the store did record the run.
		name:       "a repeat whose own bubble is out of reach is a mismatch",
		query:      "check the resolver twice",
		transcript: jsonl(turn(use("Read", resolve)), turn(use("Read", resolve)), turn(text("The resolver is bounded."))),
		bubbles: append(append([]storeRow{toolRow("r1", "read_file_v2", resolve, "package config"), said("prose", "The resolver is bounded.")},
			subagent...), toolRow("r2", "read_file_v2", resolve, "package config, again")),
		mismatch: true,
	}, {
		// Injected notification turns get no bubble, so a trailing repeat must not stamp a watermark
		// that turns an explained tail into a mismatch.
		name:  "a trailing repeat does not turn injected turns into mismatches",
		query: "find the etag helpers",
		transcript: jsonl(turn(use("Grep", etagArgs)), `{"type":"turn_ended","status":"success"}`,
			`{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:05 AM (UTC+2)</timestamp>\n\n<user_query>Briefly inform the user about the task result.</user_query>"}]}}`,
			turn(use("Grep", etagArgs)), `{"type":"turn_ended","status":"success"}`),
		bubbles: []storeRow{toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9")},
		infos:   []string{"extend past the store", "repeat"},
	}})
}
