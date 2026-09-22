package cursorjoin_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Within one turn the store's header order and the transcript's block order can disagree, so
// the match must land behind the cursor, on positive argument evidence only.
func TestAnOutOfOrderToolBubbleIsFoundBehindTheCursor(t *testing.T) {
	body := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>check types</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Spawning a typecheck subagent."},{"type":"tool_use","name":"Task","input":{"description":"Typecheck the repo","prompt":"Run npx tsc --noEmit in the repo and report errors."}}]}}
{"type":"turn_ended","status":"success"}
`
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"u1","type":1},
				{"bubbleId":"task1","type":2},
				{"bubbleId":"a1","type":2}]`),
		bubbleRow("u1", `{"bubbleId":"u1","type":1,"text":"check types"}`),
		// The store puts the task bubble before the prose, so the prose match
		// advances the cursor past it.
		bubbleRow("task1", `{"bubbleId":"task1","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"task_777","name":"task_v2","tool":38,
					"status":"completed",
					"params":"{\"description\":\"Typecheck the repo\",\"prompt\":\"Run npx tsc --noEmit in the repo and report errors.\"}",
					"result":"no type errors"}}`),
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"Spawning a typecheck subagent."}`),
	}
	d := successfulObject(t, run(t, newStore(t, rows), unit(t, body)))
	assert.Contains(t, string(d.Payload), "task_777", "the tool block did not align to the bubble behind the cursor")
}

// Neither coincidental evidence nor identical arguments may bypass the forward window.
func TestForwardWindowKeepsDistantCallsOut(t *testing.T) {
	for _, tc := range []struct{ name, input, distantArgs string }{
		{"substring coincidence", `{"pattern":"deny","glob":"**/*","output_mode":"files_with_matches"}`,
			`{"pattern":"signed","glob":"**/*.{md,json,yaml,go}"}`},
		{"identical arguments", `{"pattern":"deny_additions","path":"/work/api/internal/config"}`,
			`{"pattern":"deny_additions","path":"/work/api/internal/config"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfind the deny rules\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":` + tc.input + `}]}}
`
			headers := []string{`{"bubbleId":"b1","type":1}`, `{"bubbleId":"near","type":2}`}
			rows := []storeRow{
				bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"find the deny rules",
				"createdAt":"2026-08-18T13:59:00.000Z"}`),
				toolRow("near", "ripgrep_raw_search", `{}`, "the right result", "2026-08-18T13:59:01.000Z"),
			}
			// Twenty unrelated calls put the tempting match beyond the forward window.
			for i := range 20 {
				id := fmt.Sprintf("fill%02d", i)
				headers = append(headers, fmt.Sprintf(`{"bubbleId":%q,"type":2}`, id))
				rows = append(rows, toolRow(id, "read_file_v2", fmt.Sprintf(`{"path":"/work/api/f%02d.go"}`, i),
					"unrelated", fmt.Sprintf("2026-08-18T13:59:%02d.000Z", i+2)))
			}
			headers = append(headers, `{"bubbleId":"far","type":2}`)
			rows = append(rows,
				toolRow("far", "ripgrep_raw_search", tc.distantArgs, "the WRONG result", "2026-08-18T13:59:40.000Z"),
				composerAt(1755500000000, "["+strings.Join(headers, ",")+"]"))

			d := successfulObject(t, run(t, newStore(t, rows), unit(t, transcript)))
			lines := decode(t, d.Payload)
			e := matchedBubbles(t, lines[1], "near")[0]
			assert.Equal(t, "the right result", e["result"])
		})
	}
}

// A call recorded without arguments can never produce positive evidence, so when the header order
// leaves its bubble behind the cursor, the nearest name-compatible one behind is the last resort.
func TestATerminalBubbleLeftBehindTheCursorIsStillFound(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhat changed\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}},{"type":"tool_use","name":"Shell","input":{"command":"git status --short"}}]}}
`
	db := newStore(t, []storeRow{
		// The store's order is reversed here: the read match steps over the shell.
		composerAt(1755500000000, `[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"shell","type":2},
					{"bubbleId":"read","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"what changed",
				"createdAt":"2026-08-18T13:53:00.000Z"}`),
		toolRow("shell", "run_terminal_command_v2", `{}`,
			" M internal/config/resolve.go", "2026-08-18T13:53:01.000Z"),
		toolRow("read", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`,
			"package config", "2026-08-18T13:53:02.000Z"),
	})

	lines := joined(t, db, transcript)
	enrich := matchedBubbles(t, lines[1], "read", "shell")
	// The result is what this exists for: the terminal output the transcript has none of.
	assert.Equal(t, " M internal/config/resolve.go", enrich[1]["result"])
}

// Two argument-less shell bubbles behind the cursor, both name-compatible: nothing but position
// separates them. The nearest wins, and a change of tie-break shows up here.
func TestThePositionalLookBehindTakesTheNearestSiblingNotAnyOfThem(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhat changed\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}},{"type":"tool_use","name":"Shell","input":{"command":"git status --short"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"shellFar","type":2},{"bubbleId":"shellNear","type":2},{"bubbleId":"read","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"what changed",
				"createdAt":"2026-08-18T13:53:00.000Z"}`),
		bubbleRow("shellFar", `{"bubbleId":"shellFar","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:01.000Z",
				"toolFormerData":{"toolCallId":"call_far","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"{}","result":"the FAR sibling"}}`),
		bubbleRow("shellNear", `{"bubbleId":"shellNear","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:02.000Z",
				"toolFormerData":{"toolCallId":"call_near","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"{}","result":" M internal/config/resolve.go"}}`),
		// Matching this one on its path carries the cursor past both shells.
		toolRow("read", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`,
			"package config", "2026-08-18T13:53:03.000Z"),
	})

	lines := joined(t, db, transcript)
	e := matchedBubbles(t, lines[1], "read", "shellNear")[1]
	assert.True(t, e["result"] != "the FAR sibling", "the look-behind reached past a nearer sibling")
}

// A text block gets no positional look-behind: prose must go without provenance rather than
// borrow a neighbour's. An empty block is where the lenient rule would otherwise take anything.
func TestATextBlockDoesNotClaimAPassedOverBubbleOnPositionAlone(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhat changed\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}},{"type":"text","text":""}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"prose","type":2},{"bubbleId":"read","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"what changed",
				"createdAt":"2026-08-18T13:53:00.000Z"}`),
		// Prose of its own, which the empty block does not contradict and must not
		// be allowed to consume.
		bubbleRow("prose", `{"bubbleId":"prose","type":2,"text":"Reading the resolver first.",
				"createdAt":"2026-08-18T13:53:01.000Z"}`),
		toolRow("read", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`,
			"package config", "2026-08-18T13:53:02.000Z"),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	if e, _ := enrich[0].(map[string]any); e == nil || e["bubbleId"] != "read" {
		t.Errorf("the read joined to %v, want its own bubble", e)
	}
	// The prose carries nothing rather than the bubble the cursor walked past.
	assert.Truef(t, enrich[1] == nil, "the text block was given %v on position alone", enrich[1])
}
