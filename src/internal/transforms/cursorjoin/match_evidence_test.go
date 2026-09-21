package cursorjoin_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two agreeing values do not outvote a third that actively disagrees: under a two-of-three rule
// these two searches, differing only in pattern, swapped ids, statuses and results with no alarm.
func TestTwoCallsSharingAllButOneArgumentDoNotSwapBubbles(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncheck the goldens\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"ParseManifest|writeManifest","path":"/work/api/handlers","glob":"*.golden"}},{"type":"tool_use","name":"Grep","input":{"pattern":"VerifyPayload|checkPayload","path":"/work/api/handlers","glob":"*.golden"}}]}}
`
	db := newStore(t, []storeRow{
		{
			// The reverse of the transcript's block order within the turn.
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"createdAt":1755500000000,
				"fullConversationHeadersOnly":[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"gb","type":2},
					{"bubbleId":"ga","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"check the goldens"}`),
		bubbleRow("gb", `{"bubbleId":"gb","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_gb","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"VerifyPayload|checkPayload\",\"path\":\"/work/api/handlers\",\"glob\":\"*.golden\"}",
					"result":"payload.go:70"}}`),
		bubbleRow("ga", `{"bubbleId":"ga","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_ga","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"ParseManifest|writeManifest\",\"path\":\"/work/api/handlers\",\"glob\":\"*.golden\"}",
					"result":"manifest.go:12"}}`),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	for i, want := range []string{"ga", "gb"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s (its own bubble, not its sibling's)", i, e, want)
	}
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
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 1)
	e, _ := enrich[0].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "task", "the task joined to %v, want its own prompt-matching bubble", e)
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
		{
			// Reversed: the conflict search's bubble sits where the err search looks first.
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"createdAt":1755500000000,
				"fullConversationHeadersOnly":[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"conflict","type":2},
					{"bubbleId":"errown","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"sweep the api"}`),
		bubbleRow("conflict", `{"bubbleId":"conflict","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_conflict","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"StatusConflict|409\",\"path\":\"/work/api\"}",
					"result":"s3.go:88"}}`),
		bubbleRow("errown", `{"bubbleId":"errown","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_err","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"err\",\"path\":\"/work/api\"}",
					"result":"everywhere.go:1"}}`),
	})

	lines := joined(t, db, transcript)
	for i, want := range []string{"errown", "conflict"} {
		enrich, _ := lines[i+1]["_enrich"].([]any)
		require.Len(t, enrich, 1)
		e, _ := enrich[0].(map[string]any)
		if e == nil || e["bubbleId"] != want {
			t.Errorf("line %d joined to %v, want %s", i+1, e, want)
		}
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
		bubbleRow("r0", `{"bubbleId":"r0","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_r0","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/internal/engine/engine.go\",\"offset\":0}",
					"result":"the head of the file"}}`),
		bubbleRow("r400", `{"bubbleId":"r400","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_r400","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/internal/engine/engine.go\",\"offset\":400}",
					"result":"the tail of the file"}}`),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	for i, want := range []string{"r400", "r0"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s", i, e, want)
	}
}

// Argument evidence reaches nested inputs: comparing only top-level strings left such a tool
// permanently neutral, so under header reorder two calls of it swapped bubbles on position alone.
func TestNestedInputValuesAreArgumentEvidence(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\napply both edits\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/resolve.go","old_string":"the bound is unchecked here","new_string":"the bound is enforced here"}]}},{"type":"tool_use","name":"MultiEdit","input":{"edits":[{"file_path":"/work/api/internal/config/load.go","old_string":"loads the whole file eagerly","new_string":"streams the file in pages"}]}}]}}
`
	db := newStore(t, []storeRow{
		{
			// Reversed relative to the transcript's block order.
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"createdAt":1755500000000,
				"fullConversationHeadersOnly":[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"e2","type":2},
					{"bubbleId":"e1","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"apply both edits"}`),
		bubbleRow("e2", `{"bubbleId":"e2","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_e2","name":"multi_edit_v2",
					"status":"completed","rawArgs":"{\"edits\":[{\"file_path\":\"/work/api/internal/config/load.go\",\"old_string\":\"loads the whole file eagerly\",\"new_string\":\"streams the file in pages\"}]}",
					"result":"1 edit applied to load.go"}}`),
		bubbleRow("e1", `{"bubbleId":"e1","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_e1","name":"multi_edit_v2",
					"status":"completed","rawArgs":"{\"edits\":[{\"file_path\":\"/work/api/internal/config/resolve.go\",\"old_string\":\"the bound is unchecked here\",\"new_string\":\"the bound is enforced here\"}]}",
					"result":"1 edit applied to resolve.go"}}`),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	for i, want := range []string{"e1", "e2"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s", i, e, want)
	}
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
		{
			// An older-generation bare-string record of a DIFFERENT call that quotes
			// the search's path: containment confirms it on that one value.
			key: "bubbleId:" + conv + ":ls",
			value: `{"bubbleId":"ls","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_ls","name":"run_terminal_command_v2",
					"status":"completed",
					"rawArgs":"ls -la /work/api/internal/backends/s3/multipart",
					"result":"NOT THE SEARCH'S RESULT"}}`,
		},
		bubbleRow("grep", `{"bubbleId":"grep","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_grep","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"maxDecompressedBytes|decompressLimitCeiling\",\"path\":\"/work/api/internal/backends/s3/multipart\"}",
					"result":"multipart.go:88"}}`),
	})

	lines := joined(t, db, transcript)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 1)
	e, _ := enrich[0].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "grep", "the search joined to %v, want the bubble agreeing on both values", e)
}
