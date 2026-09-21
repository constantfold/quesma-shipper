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
		{
			// The store puts the task bubble before the prose, so the prose match
			// advances the cursor past it.
			key: "bubbleId:" + conv + ":task1",
			value: `{"bubbleId":"task1","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"task_777","name":"task_v2","tool":38,
					"status":"completed",
					"params":"{\"description\":\"Typecheck the repo\",\"prompt\":\"Run npx tsc --noEmit in the repo and report errors.\"}",
					"result":"no type errors"}}`,
		},
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"Spawning a typecheck subagent."}`),
	}
	res := run(t, newStore(t, rows), unit(t, body))
	require.Equalf(t, 0, res.Mismatched, "the out-of-order tool bubble mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	assert.Contains(t, string(res.Objects[0].Payload), "task_777", "the tool block did not align to the bubble behind the cursor")
}

// A short argument value is a substring of half the store, so comparing whole values is what
// refuses the bubble that merely starts with the same characters.
func TestACoincidentalArgumentMatchDoesNotStealADistantBubble(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfind the deny rules\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"deny","glob":"**/*","output_mode":"files_with_matches"}}]}}
`
	headers := []string{`{"bubbleId":"b1","type":1}`, `{"bubbleId":"near","type":2}`}
	rows := []storeRow{
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"find the deny rules",
				"createdAt":"2026-08-18T13:59:00.000Z"}`),
		{
			// The real bubble, recorded without arguments: positional evidence only.
			key: "bubbleId:" + conv + ":near",
			value: `{"bubbleId":"near","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:59:01.000Z",
				"toolFormerData":{"toolCallId":"call_near","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{}","result":"the right result"}}`,
		},
	}
	// Filler: enough real bubbles to put the coincidence beyond the forward window.
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("fill%02d", i)
		headers = append(headers, fmt.Sprintf(`{"bubbleId":%q,"type":2}`, id))
		rows = append(rows, storeRow{
			key: "bubbleId:" + conv + ":" + id,
			value: fmt.Sprintf(`{"bubbleId":%q,"type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:59:%02d.000Z",
				"toolFormerData":{"toolCallId":"call_%s","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/f%02d.go\"}",
					"result":"unrelated"}}`, id, i+2, id, i),
		})
	}
	// The coincidence: a DIFFERENT search, whose glob merely starts with the block's.
	headers = append(headers, `{"bubbleId":"far","type":2}`)
	rows = append(rows, bubbleRow("far", `{"bubbleId":"far","type":2,"capabilityType":15,
			"createdAt":"2026-08-18T13:59:40.000Z",
			"toolFormerData":{"toolCallId":"call_far","name":"ripgrep_raw_search",
				"status":"completed","rawArgs":"{\"pattern\":\"signed\",\"glob\":\"**/*.{md,json,yaml,go}\"}",
				"result":"the WRONG result"}}`))
	rows = append(rows, composerAt(1755500000000, "["+strings.Join(headers, ",")+"]"))

	res := run(t, newStore(t, rows), unit(t, transcript))
	require.Lenf(t, res.Objects, 1, "objects = %d, mismatched %d, notes %v", len(res.Objects), res.Mismatched, res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 1)
	e, _ := enrich[0].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "near", "the call joined to %v, want the bubble at its own position", e)
	assert.Truef(t, e["result"] == "the right result", "result = %v", e["result"])
}

// A call recorded without arguments can never produce positive evidence, so when the header order
// leaves its bubble behind the cursor, the nearest name-compatible one behind is the last resort.
func TestATerminalBubbleLeftBehindTheCursorIsStillFound(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhat changed\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}},{"type":"tool_use","name":"Shell","input":{"command":"git status --short"}}]}}
`
	db := newStore(t, []storeRow{
		{
			// The store's order is reversed here: the read match steps over the shell.
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"createdAt":1755500000000,
				"fullConversationHeadersOnly":[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"shell","type":2},
					{"bubbleId":"read","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"what changed",
				"createdAt":"2026-08-18T13:53:00.000Z"}`),
		bubbleRow("shell", `{"bubbleId":"shell","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:01.000Z",
				"toolFormerData":{"toolCallId":"call_shell","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"{}","result":" M internal/config/resolve.go"}}`),
		bubbleRow("read", `{"bubbleId":"read","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:02.000Z",
				"toolFormerData":{"toolCallId":"call_read","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/internal/config/resolve.go\"}",
					"result":"package config"}}`),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	for i, want := range []string{"read", "shell"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s", i, e, want)
	}
	// The result is what this exists for: the terminal output the transcript has none of.
	e, _ := enrich[1].(map[string]any)
	assert.Truef(t, e["result"] == " M internal/config/resolve.go", "terminal result = %v", e["result"])
}

// Distance, not discrimination: the distant bubble has the same arguments as the block, so only
// the window separates them. A conversation is not re-ordered by evidence.
func TestArgumentEvidenceDoesNotReachPastTheForwardWindow(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfind the deny rules\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"deny_additions","path":"/work/api/internal/config"}}]}}
`
	headers := []string{`{"bubbleId":"b1","type":1}`, `{"bubbleId":"near","type":2}`}
	rows := []storeRow{
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"find the deny rules",
				"createdAt":"2026-08-18T13:59:00.000Z"}`),
		bubbleRow("near", `{"bubbleId":"near","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:59:01.000Z",
				"toolFormerData":{"toolCallId":"call_near","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{}","result":"the right result"}}`),
	}
	// Calls the transcript does not mention, putting the identical one out of the window.
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("fill%02d", i)
		headers = append(headers, fmt.Sprintf(`{"bubbleId":%q,"type":2}`, id))
		rows = append(rows, storeRow{
			key: "bubbleId:" + conv + ":" + id,
			value: fmt.Sprintf(`{"bubbleId":%q,"type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:59:%02d.000Z",
				"toolFormerData":{"toolCallId":"call_%s","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/f%02d.go\"}",
					"result":"unrelated"}}`, id, i+2, id, i),
		})
	}
	// The same search much later: identical arguments, so only the window keeps the join off it.
	headers = append(headers, `{"bubbleId":"far","type":2}`)
	rows = append(rows,
		bubbleRow("far", `{"bubbleId":"far","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:59:40.000Z",
				"toolFormerData":{"toolCallId":"call_far","name":"ripgrep_raw_search",
					"status":"completed",
					"rawArgs":"{\"pattern\":\"deny_additions\",\"path\":\"/work/api/internal/config\"}",
					"result":"the WRONG result"}}`),
		composerAt(1755500000000, "["+strings.Join(headers, ",")+"]"))

	res := run(t, newStore(t, rows), unit(t, transcript))
	require.Lenf(t, res.Objects, 1, "objects = %d, mismatched %d, notes %v", len(res.Objects), res.Mismatched, res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 1)
	e, _ := enrich[0].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "near", "the call joined to %v, want the bubble at its own position", e)
	assert.Truef(t, e["result"] == "the right result", "result = %v", e["result"])
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
		{
			// Matching this one on its path carries the cursor past both shells.
			key: "bubbleId:" + conv + ":read",
			value: `{"bubbleId":"read","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:03.000Z",
				"toolFormerData":{"toolCallId":"call_read","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/internal/config/resolve.go\"}",
					"result":"package config"}}`,
		},
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	e, _ := enrich[1].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "shellNear", "the shell call joined to %v, want the nearest sibling behind the cursor", e)
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
		{
			// Prose of its own, which the empty block does not contradict and must not
			// be allowed to consume.
			key: "bubbleId:" + conv + ":prose",
			value: `{"bubbleId":"prose","type":2,"text":"Reading the resolver first.",
				"createdAt":"2026-08-18T13:53:01.000Z"}`,
		},
		bubbleRow("read", `{"bubbleId":"read","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:02.000Z",
				"toolFormerData":{"toolCallId":"call_read","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/internal/config/resolve.go\"}",
					"result":"package config"}}`),
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
