package cursorjoin_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A directory path is a prefix of every file path under it, so substring evidence made a search
// of a directory match a read of a file inside it. Whole-value comparison separates them.
func TestADirectoryArgumentDoesNotMatchAFileBeneathIt(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\naudit the config package\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"deny_additions","path":"/work/api/internal/config"}},{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"grep","type":2},{"bubbleId":"read","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"audit the config package",
				"createdAt":"2026-08-18T13:53:00.000Z"}`),
		{
			// Recorded without arguments, so only its position speaks for it.
			key: "bubbleId:" + conv + ":grep",
			value: `{"bubbleId":"grep","type":2,"capabilityType":15,
				"createdAt":"2026-08-18T13:53:01.000Z",
				"toolFormerData":{"toolCallId":"call_grep","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{}","result":"resolve.go:41"}}`,
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
	for i, want := range []string{"grep", "read"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s", i, e, want)
	}
}

// Cursor rewrites a command between the transcript and the store, splicing in its attribution.
// Unstripped, the executed form scores as contradiction on the call's own bubble.
func TestAVendorRewrittenCommandStillAligns(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncommit and open a PR\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"git commit -m \"fix: bound the loader\"","description":"Commit the fix"}},{"type":"tool_use","name":"Shell","input":{"command":"gh pr create --title \"Bound the loader\" --body \"$(cat <<'EOB'\n## Summary\n- bound it\nEOB\n)\"","description":"Open the PR"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"commit","type":2},{"bubbleId":"pr","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"commit and open a PR"}`),
		{
			// What ran: the commit with the trailer spliced in.
			key: "bubbleId:" + conv + ":commit",
			value: `{"bubbleId":"commit","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_commit","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"",
					"params":"{\"command\":\"git commit --trailer \\\"Co-authored-by: Cursor <cursoragent@cursor.com>\\\" -m \\\"fix: bound the loader\\\"\"}",
					"result":"1 file changed"}}`,
		},
		{
			// What ran: the PR body with the footer appended inside the heredoc.
			key: "bubbleId:" + conv + ":pr",
			value: `{"bubbleId":"pr","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_pr","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"",
					"params":"{\"command\":\"gh pr create --title \\\"Bound the loader\\\" --body \\\"$(cat <<'EOB'\\n## Summary\\n- bound it\\n\\nMade with [Cursor](https://cursor.com)\\nEOB\\n)\\\"\"}",
					"result":"https://github.com/org/repo/pull/1"}}`,
		},
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 0, res.Mismatched, "the rewritten commands mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 2)
	for i, want := range []string{"commit", "pr"} {
		e, _ := enrich[i].(map[string]any)
		assert.Truef(t, e != nil && e["bubbleId"] == want, "block %d joined to %v, want %s", i, e, want)
	}
}

// An errored call is recorded with no argument values at all, and recording nothing contradicts
// nothing: scored as contradiction, the bubble was barred even from the positional fallback.
func TestAnErroredCallRecordedWithoutArgumentsAligns(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfix the table\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"StrReplace","input":{"file_path":"/work/api/AUDIT.md","old_string":"| batch B | open |","new_string":"| batch B | shipped |"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"edit","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"fix the table"}`),
		{
			// The errored edit, exactly as observed: no path, no strings, just flags.
			key: "bubbleId:" + conv + ":edit",
			value: `{"bubbleId":"edit","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_edit","name":"edit_file_v2",
					"status":"error","rawArgs":"",
					"params":"{\"noCodeblock\":true,\"cloudAgentEdit\":false}",
					"result":"the model produced an invalid edit"}}`,
		},
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 0, res.Mismatched, "the errored call mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	enrich, _ := lines[1]["_enrich"].([]any)
	require.Len(t, enrich, 1)
	e, _ := enrich[0].(map[string]any)
	require.Truef(t, e != nil && e["bubbleId"] == "edit", "the block joined to %v, want the errored bubble", e)
	assert.Truef(t, e["status"] == "error", "status = %v", e["status"])
}

// The store's terminal params carry a parse tree of the command, and one of its fragments
// equalling an unrelated block's argument let that block steal the terminal bubble. The header
// order and the read's single comparable value are what make the theft happen here if the parse
// tree is allowed to speak.
func TestTheTerminalParseTreeCannotSpeakForAnotherTool(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nsurvey the repo\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"render.yaml"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"git show d63a490 -- render.yaml | head -30","description":"Inspect the pin commit"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"shell","type":2},{"bubbleId":"read","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"survey the repo"}`),
		{
			// The read's filename as a shell token, the workspace root under the
			// sandbox policy: none of it may serve as argument evidence.
			key: "bubbleId:" + conv + ":shell",
			value: `{"bubbleId":"shell","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_shell","name":"run_terminal_command_v2",
					"status":"completed","rawArgs":"",
					"params":"{\"command\":\"git show d63a490 -- render.yaml | head -30\",\"cwd\":\"\",\"parsingResult\":{\"commands\":[{\"words\":[\"git\",\"show\",\"d63a490\",\"render.yaml\",\"head\"]}]},\"requestedSandboxPolicy\":{\"workspace\":\"/work/api\"},\"commandDescription\":\"Inspect the pin commit\"}",
					"result":"render.yaml | 2 +-"}}`,
		},
		bubbleRow("read", `{"bubbleId":"read","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_read","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"render.yaml\"}",
					"result":"services:\n  - type: web"}}`),
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 0, res.Mismatched, "the parse tree stole a bubble: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	for i, want := range []string{"read", "shell"} {
		enrich, _ := lines[i+1]["_enrich"].([]any)
		require.Len(t, enrich, 1)
		e, _ := enrich[0].(map[string]any)
		if e == nil || e["bubbleId"] != want {
			t.Errorf("line %d joined to %v, want %s", i+1, e, want)
		}
	}
	// The theft's signature outcome: the shell call demoted to a repeat of nothing. Zero, or
	// the misattribution shipped silently.
	assert.Equalf(t, 0, res.Objects[0].Repeats, "repeats = %d, want 0: the shell call lost its own bubble", res.Objects[0].Repeats)
}

// One shared value among several is corroboration, not identity. The store's header order puts
// the other search first, so a rule letting the shared path speak hands over the wrong bubble.
func TestALoneSharedValueAmongSeveralIsNotIdentity(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncheck the backends\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"StatusConflict|409","path":"/work/api"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"PurgePrefix|VerifyCapabilities","path":"/work/api"}}]}}
`
	db := newStore(t, []storeRow{
		{
			// purge before conflict: the reverse of the transcript's order.
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"createdAt":1755500000000,
				"fullConversationHeadersOnly":[
					{"bubbleId":"b1","type":1},
					{"bubbleId":"purge","type":2},
					{"bubbleId":"conflict","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"check the backends"}`),
		bubbleRow("purge", `{"bubbleId":"purge","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_purge","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"PurgePrefix|VerifyCapabilities\",\"path\":\"/work/api\"}",
					"result":"purge.go:14"}}`),
		bubbleRow("conflict", `{"bubbleId":"conflict","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_conflict","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"StatusConflict|409\",\"path\":\"/work/api\"}",
					"result":"s3.go:88"}}`),
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 0, res.Mismatched, "the out-of-order pair mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	for i, want := range []string{"conflict", "purge"} {
		enrich, _ := lines[i+1]["_enrich"].([]any)
		require.Len(t, enrich, 1)
		e, _ := enrich[0].(map[string]any)
		if e == nil || e["bubbleId"] != want {
			t.Errorf("line %d joined to %v, want %s", i+1, e, want)
		}
	}
}

// The containment path — for stores that recorded arguments as a bare string — strips the
// attribution rewrite like every other comparison, in both the plain and the escaped form.
func TestABareStringStoreWithAttributionStillAligns(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncommit and open a PR\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"git commit -m \"fix: bound the loader in the manifest reader\""}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"gh pr create --title \"Bound the loader\" --body \"## Summary\n- bound it\""}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"commit","type":2},{"bubbleId":"pr","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"commit and open a PR"}`),
		{
			// A bare string, not JSON: the executed command with the trailer spliced in.
			key: "bubbleId:" + conv + ":commit",
			value: `{"bubbleId":"commit","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_commit","name":"run_terminal_command_v2",
					"status":"completed",
					"rawArgs":"git commit --trailer \"Co-authored-by: Cursor <cursoragent@cursor.com>\" -m \"fix: bound the loader in the manifest reader\"",
					"result":"1 file changed"}}`,
		},
		{
			// A bare string holding JSON: the executed command appears escaped, footer
			// included, so the escaped attribution form is the one that must strip.
			key: "bubbleId:" + conv + ":pr",
			value: `{"bubbleId":"pr","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_pr","name":"run_terminal_command_v2",
					"status":"completed",
					"rawArgs":"captured {\"command\":\"gh pr create --title \\\"Bound the loader\\\" --body \\\"## Summary\\n- bound it\\n\\nMade with [Cursor](https://cursor.com)\\\"\"} (exit 0)",
					"result":"https://github.com/org/repo/pull/1"}}`,
		},
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 0, res.Mismatched, "the rewritten bare-string commands mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)
	for i, want := range []string{"commit", "pr"} {
		enrich, _ := lines[i+1]["_enrich"].([]any)
		require.Len(t, enrich, 1)
		e, _ := enrich[0].(map[string]any)
		if e == nil || e["bubbleId"] != want {
			t.Errorf("line %d joined to %v, want %s", i+1, e, want)
		}
	}
}
