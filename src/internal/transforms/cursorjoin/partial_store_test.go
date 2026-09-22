package cursorjoin_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A wholly unmatched transcript cannot pass as a tail: no derived entry, loud alarm, raw still ships.
func TestAnUnalignedTranscriptProducesNoDerivedObjectAndAnAlarm(t *testing.T) {
	// A store describing a different conversation: what a drifted join looks like.
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"b1","type":1},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"something else entirely"}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_zzz",
				"name":"read_file","rawArgs":"{\"path\":\"/etc/hosts\"}","result":"unrelated"}}`),
	}
	res := run(t, newStore(t, rows), unit(t, transcript))

	// No derived entry: a partial one is indistinguishable downstream from a complete one.
	require.Lenf(t, res.Objects, 0, "a mismatched join still produced %d derived objects", len(res.Objects))
	assert.Equalf(t, 1, res.Mismatched, "mismatch count = %d, want 1", res.Mismatched)
	assert.NotEqual(t, 0, len(res.Notes), "a mismatch produced no note: it has to be loud, not silent")
	// The note must say what was lost, since the operator's next question is what to do.
	joined := strings.Join(res.Notes, " ")
	assert.Containsf(t, joined, "raw transcript ships", "the note does not say the raw file is unaffected: %q", joined)
}

// THE COMPACTION FIXTURE. summarizedComposers is the scenario most likely to break the join.
func TestACompactedConversationStillEnriches(t *testing.T) {
	// After compaction the header list still names bubbles whose rows are gone. Counting a
	// missing row as a mismatch would stop DB-side collection for the longest conversations.
	rows := []storeRow{
		{
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,
				"summarizedComposers":[{"summary":"earlier turns were compacted away"}],
				"fullConversationHeadersOnly":[
					{"bubbleId":"gone1","type":1},
					{"bubbleId":"gone2","type":2},
					{"bubbleId":"b1","type":1},
					{"bubbleId":"b2","type":2},
					{"bubbleId":"b3","type":2}]}`, conv),
		},
		// gone1 and gone2 have no rows: compaction removed them.
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
				"name":"run_terminal_cmd","status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}",
				"result":"total 24"}}`),
	}
	d := successfulObject(t, run(t, newStore(t, rows), unit(t, transcript)))
	assert.Contains(t, string(d.Payload), "call_abc123", "the surviving turns were not enriched")
}

// The draft skip rule: most composerData rows on a real machine are drafts.
func TestADraftConversationIsSkippedNotMismatched(t *testing.T) {
	rows := []storeRow{{
		key:   "composerData:" + conv,
		value: fmt.Sprintf(`{"composerId":%q,"fullConversationHeadersOnly":[],"conversation":[]}`, conv),
	}}
	res := run(t, newStore(t, rows), unit(t, transcript))

	// Skipped, not mismatched: only one of the two is an alarm, and drafts would bury it.
	assert.Equalf(t, 0, res.Mismatched, "a draft was counted as a mismatch: %v", res.Notes)
	assert.Equalf(t, 1, res.Skipped, "skipped = %d, want 1", res.Skipped)
	assert.Lenf(t, res.Objects, 0, "a draft produced %d derived objects", len(res.Objects))
}

func TestScaffoldingAndReasoningBubblesAreNotEvents(t *testing.T) {
	// These have no transcript counterpart; left in the event list they shift every alignment.
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"cap","type":2},
				{"bubbleId":"b1","type":1},
				{"bubbleId":"think","type":2},
				{"bubbleId":"b2","type":2},
				{"bubbleId":"b3","type":2}]`),
		bubbleRow("cap", `{"bubbleId":"cap","type":2,"isCapabilityIteration":true,"capabilityType":"tool-negotiation"}`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`),
		bubbleRow("think", `{"bubbleId":"think","type":2,"isThought":true,"text":"internal reasoning"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
				"name":"run_terminal_cmd","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}}`),
	}
	d := successfulObject(t, run(t, newStore(t, rows), unit(t, transcript)))
	// And the scaffolding must not appear as enrichment on a real block.
	assert.NotContains(t, string(d.Payload), "tool-negotiation", "a scaffolding bubble leaked into the derived object")
	assert.NotContains(t, string(d.Payload), "internal reasoning", "a thinking-only bubble leaked into the derived object")
}

// A row that still fails to decode is counted out loud: silence surfaces only as a mismatch
// alarm pointing at alignment instead.
func TestUndecodableStoreRowsProduceANote(t *testing.T) {
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
				"name":"run_terminal_cmd","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}}`),
		// A bubble row whose shape drifted beyond what the struct tolerates.
		bubbleRow("bad", `{"bubbleId":{"not":"a string"},"type":2}`),
	}
	res := run(t, newStore(t, rows), unit(t, transcript))

	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "did not decode") {
			found = true
		}
	}
	if !found {
		t.Errorf("an undecodable row produced no note: %v", res.Notes)
	}
	// And the rest of the conversation still enriches: fail open applies row by row.
	successfulObject(t, res)
}

func TestTheBubbleScanFallbackOrdersByCreatedAt(t *testing.T) {
	// The header list is empty, as observed on errored turns, so the fallback orders by
	// createdAt, the only real timestamp available.
	rows := []storeRow{
		composerRow(`[]`),
		bubbleRow("zzz", `{"bubbleId":"zzz","type":2,"text":"Listing the workspace folder contents.","createdAt":"2026-07-28T10:06:01Z"}`),
		bubbleRow("aaa", `{"bubbleId":"aaa","type":1,"text":"list the workspace","createdAt":"2026-07-28T10:06:00Z"}`),
		bubbleRow("mmm", `{"bubbleId":"mmm","type":2,"createdAt":"2026-07-28T10:06:02Z",
				"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
					"rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}}`),
	}
	d := successfulObject(t, run(t, newStore(t, rows), unit(t, transcript)))
	// Key order alone would have put aaa, mmm, zzz: createdAt is what makes this work.
	assert.Contains(t, string(d.Payload), "call_abc123", "the tool bubble did not align under the fallback ordering")
}

// A truncated tail is expected, not a failure.
func TestATruncatedTranscriptTailStillEnrichesWhatCameBefore(t *testing.T) {
	// Writes are not atomic: complete lines enrich, the fragment passes through unenriched.
	torn := transcript + `{"role":"assistant","message":{"content":[{"type":"te`
	d := successfulObject(t, run(t, fullStore(t), unit(t, torn)))
	payload := string(d.Payload)
	assert.Contains(t, payload, "call_abc123", "the complete lines were not enriched")
	// Preserved as a string, not dropped: an invalid raw value would cost the conversation,
	// and shortening the view would disagree with the transcript about where the file ended.
	assert.Contains(t, payload, "native_invalid", "the torn fragment was dropped from the derived object")
	decode(t, d.Payload)
}
