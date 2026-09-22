package cursorjoin_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The current store generation, four drifts at once: numeric tool and capabilityType enums,
// capabilityType 15 on every tool bubble, a thinking object rather than isThought, and modelName
// under modelInfo. A struct that rejects any of them drops the row and reports it as a mismatch.
func TestTheCurrentStoreGenerationEnriches(t *testing.T) {
	rows := []storeRow{
		composerAt(1753700000000, `[{"bubbleId":"u1","type":1},{"bubbleId":"think1","type":2},{"bubbleId":"a1","type":2},{"bubbleId":"tool1","type":2}]`),
		bubbleRow("u1", `{"bubbleId":"u1","type":1,"text":"list the workspace",
				"createdAt":"2026-07-28T10:06:09.499Z","requestId":"req-1"}`),
		{
			// The reasoning bubble: capabilityType 30, a thinking object, no isThought.
			key: "bubbleId:" + conv + ":think1",
			value: `{"bubbleId":"think1","type":2,"text":"","capabilityType":30,
				"thinking":{"text":"the user wants a listing","signature":"sig"},
				"createdAt":"2026-07-28T10:06:11.463Z"}`,
		},
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"Listing the workspace folder contents.\n\n\n",
				"createdAt":"2026-07-28T10:06:11.477Z","modelInfo":{"modelName":"composer-2.5"}}`),
		{
			// capabilityType 15 and toolFormerData, numeric tool, arguments in params.
			key: "bubbleId:" + conv + ":tool1",
			value: `{"bubbleId":"tool1","type":2,"text":"","capabilityType":15,
				"createdAt":"2026-07-28T10:06:11.516Z",
				"toolFormerData":{"toolCallId":"tool_33e5b6ee","name":"run_terminal_command_v2",
					"tool":15,"status":"completed","rawArgs":"",
					"params":"{\"command\":\"ls -la /work/api\",\"cwd\":\"\"}",
					"result":"{\"output\":\"total 24\\nmain.go\"}"}}`,
		},
	}
	res := run(t, newStore(t, rows), unit(t, transcript))

	require.Equalf(t, 0, res.Mismatched, "the current store generation mismatched: %v", res.Notes)
	// No decode-failure note either: every fixture row must decode.
	for _, n := range res.Notes {
		require.NotContains(t, n, "did not decode")
	}
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	lines := decode(t, res.Objects[0].Payload)

	blocks := matchedBubbles(t, lines[1], "a1", "tool1")
	assert.Equal(t, "composer-2.5", blocks[0]["modelName"])
	tool := blocks[1]
	assert.Truef(t, tool["tool_call_id"] == "tool_33e5b6ee", "tool_call_id = %v", tool["tool_call_id"])
	assert.Truef(t, tool["tool_name"] == "run_terminal_command_v2", "tool_name = %v", tool["tool_name"])
	if s, _ := tool["result"].(string); !strings.Contains(s, "main.go") {
		t.Errorf("the tool result did not make it into the derived object: %v", tool["result"])
	}
	// The thinking bubble must not leak: [REDACTED] leaves nothing to attach it to.
	assert.NotContains(t, string(res.Objects[0].Payload), "the user wants a listing", "a thinking bubble leaked into the derived object")
}

// The current transcript generation: reasoning as a plain text block, terminal bubbles with no
// recorded arguments, and injected follow-up turns that never get bubble rows.
func TestTheCurrentTranscriptGenerationEnriches(t *testing.T) {
	// Line 2's first block is the thinking text verbatim; lines 5+ are the injected turns.
	current := `{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:00 AM (UTC+2)</timestamp>\n<user_query>\nstart the dev server\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"I need to check if a dev server is already running, then start it."},{"type":"tool_use","name":"Shell","input":{"command":"pnpm dev","description":"Start the dev server"}}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"The server is up on port 5173."}]}}
{"type":"turn_ended","status":"success"}
{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:05 AM (UTC+2)</timestamp>\n\n<user_query>Briefly inform the user about the task result.</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"The dev server is running."}]}}
{"type":"turn_ended","status":"success"}
`
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"u1","type":1},
				{"bubbleId":"think1","type":2},
				{"bubbleId":"tool1","type":2},
				{"bubbleId":"a1","type":2}]`),
		bubbleRow("u1", `{"bubbleId":"u1","type":1,"text":"start the dev server"}`),
		bubbleRow("think1", `{"bubbleId":"think1","type":2,"text":"","capabilityType":30,
				"thinking":{"text":"I need to check if a dev server is already running, then start it."},
				"createdAt":"2026-08-03T07:00:01.000Z"}`),
		{
			// No recorded arguments: position and a compatible name are the evidence.
			key: "bubbleId:" + conv + ":tool1",
			value: `{"bubbleId":"tool1","type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"tool_dev123","name":"run_terminal_command_v2",
					"tool":15,"status":"completed","rawArgs":"{}","params":"",
					"result":"{\"output\":\"VITE ready on :5173\"}"}}`,
		},
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"The server is up on port 5173."}`),
	}
	res := run(t, newStore(t, rows), unit(t, current))

	require.Equalf(t, 0, res.Mismatched, "the current transcript generation mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	payload := string(res.Objects[0].Payload)

	// The thinking text block matched the thinking bubble rather than mismatching.
	lines := decode(t, res.Objects[0].Payload)
	blocks := matchedBubbles(t, lines[1], "think1", "tool1")
	assert.Equal(t, "tool_dev123", blocks[1]["tool_call_id"])
	assert.Contains(t, payload, "VITE ready", "the tool result did not reach the derived object")
	// The injected trailing turns are tail, not mismatch: carried native-only, said out
	// loud as an info — the object shipped, so it must not read as loss in Notes.
	joined := strings.Join(res.Infos, " ")
	assert.Contains(t, joined, "extend past the store")
	assert.Equal(t, 7, len(lines))
}

// The transcript side of the store's enum drift: a strict string field would reject the whole
// line, which then ships as native_invalid with its enrichment gone and mismatches at zero.
func TestATypeDriftedTranscriptLineStillDecodesAndEnriches(t *testing.T) {
	// The assistant line's role and the terminator's status arrive as numbers.
	drifted := `{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Tuesday, Jul 28, 2026, 12:06 PM (UTC+2)</timestamp>\n<user_query>\nlist the workspace\n</user_query>"}]}}
{"role":2,"message":{"content":[{"type":"text","text":"Listing the workspace folder contents."},{"type":"tool_use","name":"Shell","input":{"command":"ls -la /work/api","description":"List files in workspace root"}}]}}
{"type":"turn_ended","status":3}
`
	res := run(t, fullStore(t), unit(t, drifted))

	require.Equalf(t, 0, res.Mismatched, "the drifted lines mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	payload := string(res.Objects[0].Payload)
	assert.NotContains(t, payload, "native_invalid", "a type-drifted line was filed as invalid JSON, which it is not")
	assert.Contains(t, payload, "call_abc123", "the drifted assistant line lost its enrichment")
}

// The observed migration was string to number, but no other shape may cost the bubble either:
// a decode error in one field discards the whole row.
func TestAFlexFieldWithAnUnexpectedShapeDoesNotCostTheBubble(t *testing.T) {
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		{
			// capabilityType a bool, tool an object: shapes no store has written yet.
			key: "bubbleId:" + conv + ":b3",
			value: `{"bubbleId":"b3","type":2,"capabilityType":true,
				"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
					"tool":{"kind":15},"status":"completed",
					"rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}}`,
		},
	}
	res := run(t, newStore(t, rows), unit(t, transcript))

	for _, n := range res.Notes {
		assert.NotContainsf(t, n, "did not decode", "an unexpected scalar shape cost a whole bubble row: %s", n)
	}
	require.Equalf(t, 0, res.Mismatched, "the bubble was lost and the loss surfaced as a mismatch: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	assert.Contains(t, string(res.Objects[0].Payload), "call_abc123", "the tool bubble did not survive its drifted fields")
}

// One store holds reasoning in two encodings at once. Declaring the field an object makes
// json.Unmarshal reject the whole row of every server-hydrated thought.
func TestServerHydratedReasoningIsDecodedNotDropped(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhy is the loader bounded\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Checking where the loader's bounds are set."},{"type":"text","text":"The bound is the row cap."}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"why is the loader bounded",
				"createdAt":"2026-08-18T12:41:29.000Z"}`),
		{
			// Server-hydrated: thinking is a string holding the object.
			key: "bubbleId:" + conv + ":b2",
			value: `{"bubbleId":"b2","type":2,"capabilityType":30,
				"serverBubbleId":"srv-77","requestId":"req-2",
				"createdAt":"2026-08-18T12:41:29.766Z",
				"thinking":"{\"text\":\"Checking where the loader's bounds are set.\",\"isLastThinkingChunk\":true}"}`,
		},
		{
			// Streamed locally, in the same conversation: thinking is an object.
			key: "bubbleId:" + conv + ":b3",
			value: `{"bubbleId":"b3","type":2,"capabilityType":30,
				"thinkingStyle":1,"requestId":"req-3",
				"createdAt":"2026-08-18T12:41:49.000Z",
				"thinking":{"text":"The bound is the row cap.","signature":"sig-abc"}}`,
		},
	})

	res := run(t, db, unit(t, transcript))
	for _, n := range res.Notes {
		assert.NotContainsf(t, n, "did not decode", "a server-hydrated thought was rejected as undecodable: %s", n)
	}
	require.Truef(t, res.Mismatched <= 0, "mismatched %d: %v", res.Mismatched, res.Notes)
	require.Lenf(t, res.Objects, 1, "objects = %d, notes %v", len(res.Objects), res.Notes)

	// Both reasoning bubbles carry their provenance, whichever writer produced them.
	lines := decode(t, res.Objects[0].Payload)
	matchedBubbles(t, lines[1], "b2", "b3")
}

// A thinking string that parses but not into a known field still carries prose: taking the text
// field alone would drop the bubble out of the event list as scaffolding.
func TestAReasoningStringWithNoKnownTextFieldKeepsItsProse(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nwhy is the loader bounded\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Checking the manifest bounds."}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"why is the loader bounded",
				"createdAt":"2026-08-18T12:41:29.000Z"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"capabilityType":30,"serverBubbleId":"srv-91",
				"createdAt":"2026-08-18T12:41:29.766Z",
				"thinking":"{\"reasoning\":\"Checking the manifest bounds.\",\"isLastThinkingChunk\":true}"}`),
	})

	lines := joined(t, db, transcript)
	matchedBubbles(t, lines[1], "b2")
}
