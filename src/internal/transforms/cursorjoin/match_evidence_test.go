package cursorjoin_test

import "testing"

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
