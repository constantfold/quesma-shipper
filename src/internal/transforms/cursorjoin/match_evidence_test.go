package cursorjoin_test

import (
	"testing"
)

// Two agreeing values do not outvote a third that actively disagrees: under a two-of-three rule
// these two searches, differing only in pattern, swapped ids, statuses and results with no alarm.
func TestTwoCallsSharingAllButOneArgumentDoNotSwapBubbles(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncheck the goldens\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"ParseManifest|writeManifest","path":"/work/api/handlers","glob":"*.golden"}},{"type":"tool_use","name":"Grep","input":{"pattern":"VerifyPayload|checkPayload","path":"/work/api/handlers","glob":"*.golden"}}]}}
`
	db := newStore(t, []storeRow{
		// The reverse of the transcript's block order within the turn.
		composerAt(1755500000000, `[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"gb","type":2},
					{"bubbleId":"ga","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"check the goldens"}`),
		toolRow("gb", "ripgrep_raw_search", `{"pattern":"VerifyPayload|checkPayload","path":"/work/api/handlers","glob":"*.golden"}`,
			"payload.go:70", ""),
		toolRow("ga", "ripgrep_raw_search", `{"pattern":"ParseManifest|writeManifest","path":"/work/api/handlers","glob":"*.golden"}`,
			"manifest.go:12", ""),
	})

	lines := joined(t, db, transcript)
	matchedBubbles(t, lines[1], "ga", "gb")
}

// A bubble agreeing on a value too long to be a coincidence outranks one the store recorded
// nothing for. Here an orphaned errored task_v2 sits ahead of the call's own bubble, and
// first-neutral selection shipped the orphan's error status on a successful call.
func TestAPartiallyAgreeingOwnBubbleOutranksAnEvidenceFreeOrphan(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncheck types\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Task","input":{"prompt":"Run npx tsc --noEmit in the repo and report every error.","subagent_type":"general-purpose"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"orphan","type":2},{"bubbleId":"task","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"check types"}`),
		bubbleRow("orphan", `{"bubbleId":"orphan","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"task_orphan","name":"task_v2","tool":38,
					"status":"error","rawArgs":"{}",
					"result":"NOT THIS TASK'S RESULT"}}`),
		bubbleRow("task", `{"bubbleId":"task","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"task_real","name":"task_v2","tool":38,
					"status":"completed",
					"params":"{\"prompt\":\"Run npx tsc --noEmit in the repo and report every error.\",\"subagentType\":\"SUBAGENT_EXECUTION_ENVIRONMENT_UNSPECIFIED\"}",
					"result":"no type errors"}}`),
	})

	lines := joined(t, db, transcript)
	e := matchedBubbles(t, lines[1], "task")[0]
	if e["status"] != "completed" || e["result"] != "no type errors" {
		t.Errorf("the task wears the orphan's outcome: status=%v result=%v", e["status"], e["result"])
	}
}

// An argument shorter than minArgLen cannot confirm identity but can still deny it: with
// three-character patterns invisible to the comparison, the shared path alone certified a swap.
func TestAShortDistinguishingArgumentStillSeparatesTwoCalls(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nsweep the api\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"err","path":"/work/api"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"StatusConflict|409","path":"/work/api"}}]}}
`
	db := newStore(t, []storeRow{
		// Reversed: the conflict search's bubble sits where the err search looks first.
		composerAt(1755500000000, `[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"conflict","type":2},
					{"bubbleId":"errown","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"sweep the api"}`),
		toolRow("conflict", "ripgrep_raw_search", `{"pattern":"StatusConflict|409","path":"/work/api"}`,
			"s3.go:88", ""),
		bubbleRow("errown", `{"bubbleId":"errown","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_err","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"err\",\"path\":\"/work/api\"}",
					"result":"everywhere.go:1"}}`),
	})

	lines := joined(t, db, transcript)
	for i, want := range []string{"errown", "conflict"} {
		matchedBubbles(t, lines[i+1], want)
	}
}

// The numeric twin: numbers compare as parsed values, so the store's 1 and a transcript 1.0
// agree, and a disagreeing offset vetoes identity even though it can confirm nothing.
func TestANumericArgumentVetoesABorrowedIdentity(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nread both halves\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/engine/engine.go","offset":400}},{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/engine/engine.go","offset":0}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"r0","type":2},{"bubbleId":"r400","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"read both halves"}`),
		toolRow("r0", "read_file_v2", `{"path":"/work/api/internal/engine/engine.go","offset":0}`,
			"the head of the file", ""),
		toolRow("r400", "read_file_v2", `{"path":"/work/api/internal/engine/engine.go","offset":400}`,
			"the tail of the file", ""),
	})

	lines := joined(t, db, transcript)
	matchedBubbles(t, lines[1], "r400", "r0")
}

// Argument evidence reaches nested inputs: comparing only top-level strings left such a tool
// permanently neutral, so under header reorder two calls of it swapped bubbles on position alone.
func TestNestedInputValuesAreArgumentEvidence(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\napply both edits\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/resolve.go","old_string":"the bound is unchecked here","new_string":"the bound is enforced here"}]}},{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/load.go","old_string":"loads the whole file eagerly","new_string":"streams the file in pages"}]}}]}}
`
	db := newStore(t, []storeRow{
		// Reversed relative to the transcript's block order.
		composerAt(1755500000000, `[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"e2","type":2},
					{"bubbleId":"e1","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"apply both edits"}`),
		toolRow("e2", "multi_edit_v2", `{"edits":[{"file_path":"/work/api/internal/config/load.go","old_string":"loads the whole file eagerly","new_string":"streams the file in pages"}]}`,
			"1 edit applied to load.go", ""),
		toolRow("e1", "multi_edit_v2", `{"edits":[{"file_path":"/work/api/internal/config/resolve.go","old_string":"the bound is unchecked here","new_string":"the bound is enforced here"}]}`,
			"1 edit applied to resolve.go", ""),
	})

	lines := joined(t, db, transcript)
	matchedBubbles(t, lines[1], "e1", "e2")
}

// When two bubbles both agree in full, the one agreeing on more of the call is the call:
// first-positive-wins handed a search to a terminal record that merely quoted its path.
func TestTheStrongerOfTwoAgreeingBubblesWins(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfind the decompression bound\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"maxDecompressedBytes|decompressLimitCeiling","path":"/work/api/internal/backends/s3/multipart"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"ls","type":2},{"bubbleId":"grep","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"find the decompression bound"}`),
		// An older-generation bare-string record of a DIFFERENT call that quotes
		// the search's path: containment confirms it on that one value.
		toolRow("ls", "run_terminal_command_v2", `ls -la /work/api/internal/backends/s3/multipart`,
			"NOT THE SEARCH'S RESULT", ""),
		toolRow("grep", "ripgrep_raw_search", `{"pattern":"maxDecompressedBytes|decompressLimitCeiling","path":"/work/api/internal/backends/s3/multipart"}`,
			"multipart.go:88", ""),
	})

	lines := joined(t, db, transcript)
	matchedBubbles(t, lines[1], "grep")
}
