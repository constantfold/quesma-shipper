package cursorjoin_test

import (
	"fmt"
	"testing"
)

// How a tool block's arguments pick its bubble when store and transcript order disagree.
func TestArgumentEvidence(t *testing.T) {
	runJoinCases(t, []joinCase{{
		// Two agreeing values do not outvote a third: under two-of-three these searches swapped results.
		name:       "calls sharing all but one argument do not swap",
		query:      "check the goldens",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"ParseManifest|writeManifest","path":"/work/api/handlers","glob":"*.golden"}},{"type":"tool_use","name":"Grep","input":{"pattern":"VerifyPayload|checkPayload","path":"/work/api/handlers","glob":"*.golden"}}]}}`,
		bubbles: []storeRow{
			toolRow("gb", "ripgrep_raw_search", `{"pattern":"VerifyPayload|checkPayload","path":"/work/api/handlers","glob":"*.golden"}`, "payload.go:70"),
			toolRow("ga", "ripgrep_raw_search", `{"pattern":"ParseManifest|writeManifest","path":"/work/api/handlers","glob":"*.golden"}`, "manifest.go:12"),
		},
		want: map[int][]string{1: {"ga", "gb"}},
	}, {
		// A value too long to be a coincidence outranks a bubble with nothing recorded.
		name:       "a partially agreeing own bubble outranks an evidence-free orphan",
		query:      "check types",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Task","input":{"prompt":"Run npx tsc --noEmit in the repo and report every error.","subagent_type":"general-purpose"}}]}}`,
		bubbles: []storeRow{
			tool{id: "orphan", name: "task_v2", status: "error", rawArgs: "{}", result: "NOT THIS TASK'S RESULT"}.row(),
			tool{id: "task", name: "task_v2", result: "no type errors",
				params: `{"prompt":"Run npx tsc --noEmit in the repo and report every error.","subagentType":"SUBAGENT_EXECUTION_ENVIRONMENT_UNSPECIFIED"}`}.row(),
		},
		want: map[int][]string{1: {"task"}},
	}, {
		// A value shorter than minArgLen cannot confirm identity but can deny it.
		name:  "a short distinguishing argument separates two calls",
		query: "sweep the api",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"err","path":"/work/api"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"StatusConflict|409","path":"/work/api"}}]}}`,
		bubbles: []storeRow{
			toolRow("conflict", "ripgrep_raw_search", `{"pattern":"StatusConflict|409","path":"/work/api"}`, "s3.go:88"),
			toolRow("errown", "ripgrep_raw_search", `{"pattern":"err","path":"/work/api"}`, "everywhere.go:1"),
		},
		want: map[int][]string{1: {"errown"}, 2: {"conflict"}},
	}, {
		// Numbers compare as parsed values, and a disagreeing offset vetoes though it confirms nothing.
		name:       "a numeric argument vetoes a borrowed identity",
		query:      "read both halves",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/engine/engine.go","offset":400}},{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/engine/engine.go","offset":0}}]}}`,
		bubbles: []storeRow{
			toolRow("r0", "read_file_v2", `{"path":"/work/api/internal/engine/engine.go","offset":0}`, "the head of the file"),
			toolRow("r400", "read_file_v2", `{"path":"/work/api/internal/engine/engine.go","offset":400}`, "the tail of the file"),
		},
		want: map[int][]string{1: {"r400", "r0"}},
	}, {
		// Comparing only top-level strings left nested inputs neutral, so two calls swapped on position.
		name:       "nested input values are argument evidence",
		query:      "apply both edits",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/resolve.go","old_string":"the bound is unchecked here","new_string":"the bound is enforced here"}]}},{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/load.go","old_string":"loads the whole file eagerly","new_string":"streams the file in pages"}]}}]}}`,
		bubbles: []storeRow{
			toolRow("e2", "multi_edit_v2", `{"edits":[{"file_path":"/work/api/internal/config/load.go","old_string":"loads the whole file eagerly","new_string":"streams the file in pages"}]}`, "1 edit applied to load.go"),
			toolRow("e1", "multi_edit_v2", `{"edits":[{"file_path":"/work/api/internal/config/resolve.go","old_string":"the bound is unchecked here","new_string":"the bound is enforced here"}]}`, "1 edit applied to resolve.go"),
		},
		want: map[int][]string{1: {"e1", "e2"}},
	}, {
		// Of two fully agreeing bubbles, the one agreeing on more is the call.
		name:       "the stronger of two agreeing bubbles wins",
		query:      "find the decompression bound",
		transcript: `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"maxDecompressedBytes|decompressLimitCeiling","path":"/work/api/internal/backends/s3/multipart"}}]}}`,
		bubbles: []storeRow{
			toolRow("ls", "run_terminal_command_v2", `ls -la /work/api/internal/backends/s3/multipart`, "NOT THE SEARCH'S RESULT"),
			toolRow("grep", "ripgrep_raw_search", `{"pattern":"maxDecompressedBytes|decompressLimitCeiling","path":"/work/api/internal/backends/s3/multipart"}`, "multipart.go:88"),
		},
		want: map[int][]string{1: {"grep"}},
	}})
}

// Tool-specific shapes of the stored arguments: what they must not match, and what they still must.
func TestToolArgumentShapes(t *testing.T) {
	runJoinCases(t, []joinCase{{
		// A directory path is a prefix of every file under it.
		name:       "a directory argument does not match a file beneath it",
		query:      "audit the config package",
		transcript: turn(use("Grep", `{"pattern":"deny_additions","path":"/work/api/internal/config"}`), use("Read", `{"path":"/work/api/internal/config/resolve.go"}`)),
		bubbles: []storeRow{
			toolRow("grep", "ripgrep_raw_search", `{}`, "resolve.go:41"),
			toolRow("read", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`, "package config"),
		},
		want: map[int][]string{1: {"grep", "read"}},
	}, {
		// Cursor splices its attribution into what ran; unstripped, that scores as contradiction.
		name:  "a vendor-rewritten command still aligns",
		query: "commit and open a PR",
		transcript: turn(use("Shell", `{"command":"git commit -m \"fix: bound the loader\"","description":"Commit the fix"}`),
			use("Shell", `{"command":"gh pr create --title \"Bound the loader\" --body \"$(cat <<'EOB'\n## Summary\n- bound it\nEOB\n)\"","description":"Open the PR"}`)),
		bubbles: []storeRow{
			tool{id: "commit", name: "run_terminal_command_v2", result: "1 file changed",
				params: `{"command":"git commit --trailer \"Co-authored-by: Cursor <cursoragent@cursor.com>\" -m \"fix: bound the loader\""}`}.row(),
			tool{id: "pr", name: "run_terminal_command_v2", result: "https://github.com/org/repo/pull/1",
				params: `{"command":"gh pr create --title \"Bound the loader\" --body \"$(cat <<'EOB'\n## Summary\n- bound it\n\nMade with [Cursor](https://cursor.com)\nEOB\n)\""}`}.row(),
		},
		want: map[int][]string{1: {"commit", "pr"}},
	}, {
		// The containment path for bare-string records strips the attribution too, plain and escaped.
		name:  "a bare-string store with attribution still aligns",
		query: "commit and open a PR",
		transcript: jsonl(turn(use("Shell", `{"command":"git commit -m \"fix: bound the loader in the manifest reader\""}`)),
			turn(use("Shell", `{"command":"gh pr create --title \"Bound the loader\" --body \"## Summary\n- bound it\""}`))),
		bubbles: []storeRow{
			toolRow("commit", "run_terminal_command_v2", `git commit --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>" -m "fix: bound the loader in the manifest reader"`, "1 file changed"),
			// A bare string holding JSON: the footer appears escaped.
			toolRow("pr", "run_terminal_command_v2", `captured {"command":"gh pr create --title \"Bound the loader\" --body \"## Summary\n- bound it\n\nMade with [Cursor](https://cursor.com)\""} (exit 0)`, "https://github.com/org/repo/pull/1"),
		},
		want: map[int][]string{1: {"commit"}, 2: {"pr"}},
	}, {
		// An errored call records only flags, and recording nothing contradicts nothing.
		name:       "an errored call recorded without arguments aligns",
		query:      "fix the table",
		transcript: turn(use("StrReplace", `{"file_path":"/work/api/AUDIT.md","old_string":"| batch B | open |","new_string":"| batch B | shipped |"}`)),
		bubbles: []storeRow{tool{id: "edit", name: "edit_file_v2", status: "error",
			params: `{"noCodeblock":true,"cloudAgentEdit":false}`, result: "the model produced an invalid edit"}.row()},
		want: map[int][]string{1: {"edit"}},
	}, {
		// A fragment of the terminal parse tree equal to the read's only value must not steal the bubble.
		name:  "the terminal parse tree cannot speak for another tool",
		query: "survey the repo",
		transcript: jsonl(turn(use("Read", `{"file_path":"render.yaml"}`)),
			turn(use("Shell", `{"command":"git show d63a490 -- render.yaml | head -30","description":"Inspect the pin commit"}`))),
		bubbles: []storeRow{
			tool{id: "shell", name: "run_terminal_command_v2", result: "render.yaml | 2 +-",
				params: `{"command":"git show d63a490 -- render.yaml | head -30","cwd":"","parsingResult":{"commands":[{"words":["git","show","d63a490","render.yaml","head"]}]},"requestedSandboxPolicy":{"workspace":"/work/api"},"commandDescription":"Inspect the pin commit"}`}.row(),
			toolRow("read", "read_file_v2", `{"path":"render.yaml"}`, "services:\n  - type: web"),
		},
		want: map[int][]string{1: {"read"}, 2: {"shell"}},
	}, {
		// One shared value among several is corroboration, not identity.
		name:       "a lone shared value among several is not identity",
		query:      "check the backends",
		transcript: jsonl(turn(use("Grep", `{"pattern":"StatusConflict|409","path":"/work/api"}`)), turn(use("Grep", `{"pattern":"PurgePrefix|VerifyCapabilities","path":"/work/api"}`))),
		bubbles: []storeRow{
			toolRow("purge", "ripgrep_raw_search", `{"pattern":"PurgePrefix|VerifyCapabilities","path":"/work/api"}`, "purge.go:14"),
			toolRow("conflict", "ripgrep_raw_search", `{"pattern":"StatusConflict|409","path":"/work/api"}`, "s3.go:88"),
		},
		want: map[int][]string{1: {"conflict"}, 2: {"purge"}},
	}})
}

// Where the matcher looks: behind the cursor for out-of-order bubbles, never past the forward window.
func TestMatchWindows(t *testing.T) {
	var far []storeRow
	for i := range 20 {
		far = append(far, toolRow(fmt.Sprintf("fill%02d", i), "read_file_v2", fmt.Sprintf(`{"path":"/work/api/f%02d.go"}`, i), "unrelated"))
	}
	// Twenty unrelated calls put a tempting match beyond the forward window.
	beyondWindow := func(name, input, distantArgs string) joinCase {
		return joinCase{
			name:       name,
			query:      "find the deny rules",
			transcript: turn(use("Grep", input)),
			bubbles: append(append([]storeRow{toolRow("near", "ripgrep_raw_search", `{}`, "the right result")}, far...),
				toolRow("far", "ripgrep_raw_search", distantArgs, "the WRONG result")),
			want: map[int][]string{1: {"near"}},
		}
	}
	const read = `{"path":"/work/api/internal/config/resolve.go"}`
	runJoinCases(t, []joinCase{
		beyondWindow("substring coincidence stays out of reach", `{"pattern":"deny","glob":"**/*","output_mode":"files_with_matches"}`,
			`{"pattern":"signed","glob":"**/*.{md,json,yaml,go}"}`),
		beyondWindow("identical arguments stay out of reach", `{"pattern":"deny_additions","path":"/work/api/internal/config"}`,
			`{"pattern":"deny_additions","path":"/work/api/internal/config"}`),
		{
			// The store puts the task before the prose, so the prose match advances the cursor past it.
			name:       "an out-of-order tool bubble is found behind the cursor",
			query:      "check types",
			transcript: turn(text("Spawning a typecheck subagent."), use("Task", `{"description":"Typecheck the repo","prompt":"Run npx tsc --noEmit in the repo and report errors."}`)),
			bubbles: []storeRow{
				tool{id: "task1", name: "task_v2", result: "no type errors",
					params: `{"description":"Typecheck the repo","prompt":"Run npx tsc --noEmit in the repo and report errors."}`}.row(),
				said("a1", "Spawning a typecheck subagent."),
			},
			want: map[int][]string{1: {"a1", "task1"}},
		}, {
			// An argument-less call never grades positive: the nearest name-compatible bubble is the last resort.
			name:       "a terminal bubble left behind the cursor is still found",
			query:      "what changed",
			transcript: turn(use("Read", read), use("Shell", `{"command":"git status --short"}`)),
			bubbles: []storeRow{
				toolRow("shell", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go"),
				toolRow("read", "read_file_v2", read, "package config"),
			},
			want: map[int][]string{1: {"read", "shell"}},
		}, {
			// Nothing but position separates two argument-less siblings: the nearest wins.
			name:       "the positional look-behind takes the nearest sibling",
			query:      "what changed",
			transcript: turn(use("Read", read), use("Shell", `{"command":"git status --short"}`)),
			bubbles: []storeRow{
				toolRow("shellFar", "run_terminal_command_v2", `{}`, "the FAR sibling"),
				toolRow("shellNear", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go"),
				toolRow("read", "read_file_v2", read, "package config"),
			},
			want: map[int][]string{1: {"read", "shellNear"}},
		}, {
			// Prose gets no positional look-behind: an empty block would otherwise take anything.
			name:       "a text block does not claim a passed-over bubble on position alone",
			query:      "what changed",
			transcript: turn(use("Read", read), text("")),
			bubbles:    []storeRow{said("prose", "Reading the resolver first."), toolRow("read", "read_file_v2", read, "package config")},
			want:       map[int][]string{1: {"read", ""}},
		},
	})
}

const (
	etagArgs  = `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`
	purgeArgs = `{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}`
)

// A call the store recorded once attaches and consumes nothing: it hides no hole, takes no bubble.
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
		// The re-run could be the argument-less bubble, so it ships undecided and that bubble stays barred.
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
		// Only an identity-grade consumer makes a later agreeing call a repeat, not a positional one.
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
		// Repeat detection is not bounded by the look-behind window: 64 consumed calls sit in between.
		name:       "a store-deduped re-run far back is still a repeat",
		query:      "audit everything",
		transcript: jsonl(append(append([]string{turn(use("Grep", etagArgs))}, farBack...), turn(use("Grep", etagArgs)), turn(text("All checks passed.")))...),
		bubbles:    append(append([]storeRow{toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9")}, farBackRows...), said("a1", "All checks passed.")),
		infos:      []string{"repeat"},
	}, {
		// The re-run's own bubble sits past the forward window, so the store did record it.
		name:       "a repeat whose own bubble is out of reach is a mismatch",
		query:      "check the resolver twice",
		transcript: jsonl(turn(use("Read", resolve)), turn(use("Read", resolve)), turn(text("The resolver is bounded."))),
		bubbles: append(append([]storeRow{toolRow("r1", "read_file_v2", resolve, "package config"), said("prose", "The resolver is bounded.")},
			subagent...), toolRow("r2", "read_file_v2", resolve, "package config, again")),
		mismatch: true,
	}, {
		// Injected turns get no bubble; a trailing repeat must not turn that tail into a mismatch.
		name:  "a trailing repeat does not turn injected turns into mismatches",
		query: "find the etag helpers",
		transcript: jsonl(turn(use("Grep", etagArgs)), `{"type":"turn_ended","status":"success"}`,
			`{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:05 AM (UTC+2)</timestamp>\n\n<user_query>Briefly inform the user about the task result.</user_query>"}]}}`,
			turn(use("Grep", etagArgs)), `{"type":"turn_ended","status":"success"}`),
		bubbles: []storeRow{toolRow("grep", "ripgrep_raw_search", etagArgs, "etag.go:9")},
		infos:   []string{"extend past the store", "repeat"},
	}})
}
