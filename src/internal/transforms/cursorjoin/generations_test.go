package cursorjoin_test

import "testing"

// Vendor drift on either side. A struct that rejects a drifted field drops the whole row or line,
// which then reports as a mismatch or ships unenriched.
func TestStoreAndTranscriptGenerations(t *testing.T) {
	const loaderQuery = "why is the loader bounded"
	runJoinCases(t, []joinCase{{
		// Four drifts at once: numeric tool and capabilityType enums, capabilityType 15 on every tool
		// bubble, a thinking object rather than isThought, and modelName under modelInfo.
		name: "the current store generation",
		rows: conversation(
			user("b1", "list the workspace"),
			bubbleRow("think1", `{"type":2,"text":"","capabilityType":30,"thinking":{"text":"the user wants a listing","signature":"sig"}}`),
			bubbleRow("a1", `{"type":2,"text":"Listing the workspace folder contents.\n\n\n","modelInfo":{"modelName":"composer-2.5"}}`),
			bubbleRow("tool1", `{"type":2,"text":"","capabilityType":15,"toolFormerData":{"toolCallId":"tool_33e5b6ee",
				"name":"run_terminal_command_v2","tool":15,"status":"completed","rawArgs":"",
				"params":"{\"command\":\"ls -la /work/api\",\"cwd\":\"\"}","result":"{\"output\":\"total 24\\nmain.go\"}"}}`),
		),
		want:    map[int][]string{1: {"a1", "tool1"}},
		present: []string{"composer-2.5"},
		// [REDACTED] reasoning leaves nothing to attach the thinking bubble to.
		absent: []string{"the user wants a listing"},
	}, {
		// Reasoning as a plain text block, a terminal call with no recorded arguments, and injected
		// follow-up turns that never get bubble rows: tail, carried native-only as an info.
		name: "the current transcript generation",
		transcript: jsonl(
			`{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:00 AM (UTC+2)</timestamp>\n<user_query>\nstart the dev server\n</user_query>"}]}}`,
			turn(text("I need to check if a dev server is already running, then start it."), use("Shell", `{"command":"pnpm dev","description":"Start the dev server"}`)),
			turn(text("The server is up on port 5173.")),
			`{"type":"turn_ended","status":"success"}`,
			`{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:05 AM (UTC+2)</timestamp>\n\n<user_query>Briefly inform the user about the task result.</user_query>"}]}}`,
			turn(text("The dev server is running.")),
			`{"type":"turn_ended","status":"success"}`),
		bubbles: []storeRow{
			user("b1", "start the dev server"),
			bubbleRow("think1", `{"type":2,"text":"","capabilityType":30,"thinking":{"text":"I need to check if a dev server is already running, then start it."}}`),
			tool{id: "tool1", name: "run_terminal_command_v2", rawArgs: "{}", result: `{"output":"VITE ready on :5173"}`}.row(),
			said("a1", "The server is up on port 5173."),
		},
		want:    map[int][]string{1: {"think1", "tool1"}, 2: {"a1"}},
		present: []string{"VITE ready"},
		infos:   []string{"extend past the store"},
	}, {
		// The assistant line's role and the terminator's status arrive as numbers.
		name: "a type-drifted transcript line still decodes",
		transcript: `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nlist the workspace\n</user_query>"}]}}
{"role":2,"message":{"content":[{"type":"text","text":"Listing the workspace folder contents."},{"type":"tool_use","name":"Shell","input":{"command":"ls -la /work/api"}}]}}
{"type":"turn_ended","status":3}`,
		rows:   fullRows(),
		want:   map[int][]string{1: {"b2", "b3"}},
		absent: []string{"native_invalid"},
	}, {
		// capabilityType a bool, tool an object: shapes no store has written yet must not cost the row.
		name: "a flex field with an unexpected shape",
		rows: lsRows(`"capabilityType":true,"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
			"tool":{"kind":15},"status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}`),
		want: map[int][]string{1: {"b2", "b3"}},
	}, {
		// One store holds reasoning in two encodings: server-hydrated thinking is a string holding the
		// object, locally streamed thinking is the object.
		name:       "server-hydrated reasoning is decoded, not dropped",
		query:      loaderQuery,
		transcript: turn(text("Checking where the loader's bounds are set."), text("The bound is the row cap.")),
		bubbles: []storeRow{
			bubbleRow("b2", `{"type":2,"capabilityType":30,"thinking":"{\"text\":\"Checking where the loader's bounds are set.\",\"isLastThinkingChunk\":true}"}`),
			bubbleRow("b3", `{"type":2,"capabilityType":30,"thinking":{"text":"The bound is the row cap.","signature":"sig-abc"}}`),
		},
		want: map[int][]string{1: {"b2", "b3"}},
	}, {
		// Taking the known text field alone would drop this bubble out of the event list as scaffolding.
		name:       "a reasoning string with no known text field keeps its prose",
		query:      loaderQuery,
		transcript: turn(text("Checking the manifest bounds.")),
		bubbles: []storeRow{bubbleRow("b2", `{"type":2,"capabilityType":30,
			"thinking":"{\"reasoning\":\"Checking the manifest bounds.\",\"isLastThinkingChunk\":true}"}`)},
		want: map[int][]string{1: {"b2"}},
	}})
}
