package cursorjoin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

// THE JOIN: what the transcript cannot say, beside the native lines, with provenance, deterministically.
func TestTheJoinCarriesTheFieldsTheTranscriptLacks(t *testing.T) {
	d := successfulObject(t, run(t, fullRows(), transcript))
	require.Equal(t, transforms.StatusOK, d.Status)
	assert.Truef(t, strings.HasSuffix(d.NativePath, conv+".jsonl.enriched.jsonl"), "derived path = %s", d.NativePath)

	lines := decode(t, d.Payload)
	require.Len(t, lines, 3, "one derived line per transcript line")
	tool := matchedBubbles(t, lines[1], "b2", "b3")[1]
	assert.Equal(t, "call_abc123", tool["tool_call_id"])
	assert.Equal(t, "completed", tool["status"])
	assert.Equal(t, "run_terminal_cmd", tool["tool_name"], "the INTERNAL name, not the transcript's display name")
	assert.Contains(t, tool["result"], "main.go")
	// A real timestamp, where the transcript's only time signal is prose in a user message.
	assert.Equal(t, "2026-07-28T10:06:02.000Z", tool["createdAt"])

	// Byte-identical, not merely equivalent: downstream verifies the derived object against the raw file.
	want := strings.Split(strings.TrimRight(transcript, "\n"), "\n")
	for i, line := range strings.Split(strings.TrimRight(string(d.Payload), "\n"), "\n") {
		var m struct{ Native json.RawMessage }
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		assert.Equalf(t, want[i], string(m.Native), "line %d was re-encoded", i)
	}

	// Without the pairing, a derived object is an assertion nobody can check.
	assert.Equal(t, []string{unit(transcript).SourceHash}, d.DerivedFrom)
	assert.NotEmpty(t, d.DBReadMethod)
	assert.NotZero(t, d.DBRowsRead)
	assert.Equal(t, []string{"composerData:", "bubbleId:"}, d.DBKeyspaces, "provenance records the declared scope")

	// Same input values, same output bytes, or the hash stops being a change signal.
	again := successfulObject(t, run(t, fullRows(), transcript))
	assert.Equal(t, string(d.Payload), string(again.Payload))
	assert.Equal(t, d.OutputHash, again.OutputHash)

	// A DB-side-only update: the transcript is byte-identical, so only the output hash can signal it.
	after := successfulObject(t, run(t, lsRows(`"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
		"status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"total 24\nA LATE RESULT ARRIVED"}`), transcript))
	assert.NotEqual(t, d.OutputHash, after.OutputHash, "a DB-side-only change would never ship")
	assert.Contains(t, string(after.Payload), "A LATE RESULT ARRIVED")
}

// No database is not an error, and an unreadable one fails open with a count.
func TestAMissingOrUnreadableDatabaseFailsOpen(t *testing.T) {
	res := enrichAt(t, "", transcript)
	assert.Equal(t, transforms.EnrichResult{Skipped: 1, Notes: []string{"no state.vscdb found: raw transcripts only"}}, res)

	path := filepath.Join(t.TempDir(), "state.vscdb")
	require.NoError(t, os.WriteFile(path, []byte("this is not a database"), 0o600))
	res = enrichAt(t, path, transcript)
	assert.Empty(t, res.Objects)
	assert.Equal(t, 1, res.Errors)
	assert.NotEmpty(t, res.Notes, "an unreadable database produced no note")
}

// Only the global store is declared; the workspace state.vscdb is deferred.
func TestOnlyTheGlobalStoreIsDeclared(t *testing.T) {
	for _, c := range cursorjoin.New().DBCandidates() {
		assert.Contains(t, c, "globalStorage")
	}
}

// Vendor drift on either side: a struct rejecting a drifted field would drop the whole row or line.
func TestStoreAndTranscriptGenerations(t *testing.T) {
	const loaderQuery = "why is the loader bounded"
	runJoinCases(t, []joinCase{{
		// Numeric enums, capabilityType 15 on tool bubbles, a thinking object, modelInfo.modelName.
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
		// Reasoning as text, an argument-less terminal call, and injected turns with no rows (tail).
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
		// Server-hydrated thinking is a string holding the object, locally streamed thinking the object.
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

// Stores that account for less than the transcript, or more than the join reads.
func TestPartialStores(t *testing.T) {
	runJoinCases(t, []joinCase{{
		// A store describing a different conversation cannot pass as a tail.
		name:     "an unaligned transcript is an alarm, not an object",
		rows:     conversation(user("b1", "something else entirely"), lsBubble(`"toolFormerData":{"name":"read_file","rawArgs":"{\"path\":\"/etc/hosts\"}"}`)),
		mismatch: true,
	}, {
		// THE COMPACTION FIXTURE: headers still name bubbles whose rows are gone.
		name: "a compacted conversation still enriches",
		rows: append([]storeRow{{"composerData:" + conv, `{"summarizedComposers":[{"summary":"earlier turns were compacted away"}],
			"fullConversationHeadersOnly":[{"bubbleId":"gone1"},{"bubbleId":"gone2"},{"bubbleId":"b1"},{"bubbleId":"b2"},{"bubbleId":"b3"}]}`}},
			lsRows(lsTool)[1:]...),
		want: map[int][]string{1: {"b2", "b3"}},
	}, {
		// Neither has a transcript counterpart; left in the event list they shift every alignment.
		name: "scaffolding and reasoning bubbles are not events",
		rows: conversation(
			bubbleRow("cap", `{"type":2,"isCapabilityIteration":true,"capabilityType":"tool-negotiation"}`),
			user("b1", "list the workspace"),
			bubbleRow("think", `{"type":2,"isThought":true,"text":"internal reasoning"}`),
			said("b2", "Listing the workspace folder contents."),
			lsBubble(lsTool)),
		want:   map[int][]string{1: {"b2", "b3"}},
		absent: []string{"tool-negotiation", "internal reasoning"},
	}, {
		// An empty header list, as on errored turns: key order would put aaa, mmm, zzz.
		name: "the bubble scan fallback orders by createdAt",
		rows: append(conversation(),
			bubbleRow("zzz", `{"type":2,"text":"Listing the workspace folder contents.","createdAt":"2026-07-28T10:06:01Z"}`),
			bubbleRow("aaa", `{"type":1,"text":"list the workspace","createdAt":"2026-07-28T10:06:00Z"}`),
			bubbleRow("mmm", `{"type":2,"createdAt":"2026-07-28T10:06:02Z",`+lsTool+`}`)),
		want: map[int][]string{0: {"aaa"}, 1: {"zzz", "mmm"}},
	}, {
		// Writes are not atomic: complete lines enrich, and the torn fragment is kept as a string.
		name:       "a truncated transcript tail still enriches what came before",
		transcript: transcript + `{"role":"assistant","message":{"content":[{"type":"te`,
		rows:       fullRows(),
		want:       map[int][]string{1: {"b2", "b3"}},
		present:    []string{"native_invalid"},
	}, {
		// THE NO-ROWS RULE: the derived object is a join of named fields, not a dump.
		name: "no store row reaches the derived object wholesale",
		rows: []storeRow{
			{"composerData:" + conv, `{"UNUSED_MARKER":"must-not-ship","fullConversationHeadersOnly":[{"bubbleId":"b1"},{"bubbleId":"b2"},{"bubbleId":"b3"}]}`},
			bubbleRow("b1", `{"type":1,"text":"list the workspace","ALSO_UNUSED":"must-not-ship"}`),
			said("b2", "Listing the workspace folder contents."),
			lsBubble(lsTool),
		},
		want:   map[int][]string{1: {"b2", "b3"}},
		absent: []string{"UNUSED_MARKER", "ALSO_UNUSED", "must-not-ship"},
	}})
}

// Most composerData rows on a real machine are drafts: skipped, not mismatched, or they bury the alarm.
func TestADraftConversationIsSkippedNotMismatched(t *testing.T) {
	res := run(t, []storeRow{{"composerData:" + conv, `{"fullConversationHeadersOnly":[],"conversation":[]}`}}, transcript)
	assert.Zerof(t, res.Mismatched, "notes: %v", res.Notes)
	assert.Equal(t, 1, res.Skipped)
	assert.Empty(t, res.Objects)
}

// A row that fails to decode is counted out loud, and the rest of the conversation still enriches.
func TestUndecodableStoreRowsProduceANote(t *testing.T) {
	res := run(t, append(lsRows(lsTool), bubbleRow("bad", `{"bubbleId":{"not":"a string"},"type":2}`)), transcript)
	assert.Contains(t, strings.Join(res.Notes, " "), "did not decode")
	successfulObject(t, res)
}
