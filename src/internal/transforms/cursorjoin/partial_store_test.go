package cursorjoin_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
