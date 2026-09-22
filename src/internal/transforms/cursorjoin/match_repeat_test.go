package cursorjoin_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The store records one bubble for identical repeated calls — but the same evidence also fits a
// store that recorded both runs, the second argument-less. Each reading makes the other's
// attachment wrong, so the re-run ships undecided: nothing attached, no alarm, and the
// argument-less bubble barred from later fallbacks.
func TestARepeatedCallTheStoreRecordedOnceIsNotAMismatch(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nlook twice\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Both live in etag.go."}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"grep","type":2},{"bubbleId":"argless","type":2},{"bubbleId":"purge","type":2},{"bubbleId":"a1","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"look twice"}`),
		toolRow("grep", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`,
			"etag.go:9", ""),
		// An argument-less same-named bubble right where a positional fallback would
		// look. The repeat must not take it — its result is some other call's.
		toolRow("argless", "ripgrep_raw_search", `{}`, "NOT THE REPEAT'S RESULT", ""),
		// A following sibling of the same tool: the repeat must leave its bubble alone.
		toolRow("purge", "ripgrep_raw_search", `{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}`,
			"purge.go:14", ""),
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"Both live in etag.go."}`),
	})

	d := successfulObject(t, run(t, db, unit(t, transcript)))
	lines := decode(t, d.Payload)

	matchedBubbles(t, lines[1], "grep")
	assert.NotContains(t, lines[2], "_enrich", "the repeat has no recorded bubble")
	matchedBubbles(t, lines[3], "purge")
	matchedBubbles(t, lines[4], "a1")
	// The argument-less bubble's result must not surface ANYWHERE: not on the re-run, and
	// not on a later call the declined bubble could otherwise fall back to.
	assert.NotContains(t, string(d.Payload), "NOT THE REPEAT'S RESULT", "the undecided argument-less bubble's result reached the derived object")
}

// A hole before a repeat is still a hole, but the repeat is not what proves it: it consumes
// nothing, so the next consuming match is what catches the hole. The trailing case — where
// stamping a watermark discards vendor-explained conversations — is asserted in
// TestATrailingRepeatDoesNotTurnInjectedTurnsIntoMismatches.
func TestAHoleBeforeARepeatIsAMismatchNotTail(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nlook around\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"nothing|the|store|knows","path":"/work/api/internal/engine"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"grep","type":2},{"bubbleId":"purge","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"look around"}`),
		toolRow("grep", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`,
			"etag.go:9", ""),
		toolRow("purge", "ripgrep_raw_search", `{"pattern":"PurgePrefix|opts\\.Prefix","path":"/work/api/internal/backends/s3"}`,
			"purge.go:14", ""),
	})

	res := run(t, db, unit(t, transcript))
	require.Equalf(t, 1, res.Mismatched, "mismatched = %d, want 1 (the hole sits before a consuming match): %v", res.Mismatched, res.Notes)
	require.Lenf(t, res.Objects, 0, "the hole rode out on the tail rule: %v", res.Notes)
}

// A bubble consumed by a positional fallback is not proof of a dedup: reading it as one files
// the bubble's real owner as a repeat and ships the fallback's block wearing the wrong result.
// Only an identity-grade consumer can make a later agreeing call a repeat.
func TestAFallbackConsumerDoesNotMakeTheNextCallARepeat(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nscan the backends\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"PurgePrefix|opts","path":"/work/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/s3"}}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Both live in etag.go."}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"etag","type":2},{"bubbleId":"a1","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"scan the backends"}`),
		// The only tool bubble. It belongs to the second search, but the first
		// reaches it first and the shared path keeps it un-contradicted.
		toolRow("etag", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/s3"}`,
			"etag.go:9", ""),
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"Both live in etag.go."}`),
	})

	res := run(t, db, unit(t, transcript))
	require.Equal(t, 1, res.Mismatched)
	require.Lenf(t, res.Objects, 0, "shipped a derived object built on a fallback-certified repeat: %v", res.Infos)
}

// The undecided bubble must not drift to an unrelated later call: left unconsumed, the next
// terminal command took it as its positional fallback and shipped wearing the re-run's result.
func TestAnUndecidableRepeatAttachesNothingAndDoesNotCascade(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nrun the tests\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"npm test"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"npm test"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"git status --short"}}]}}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"t1","type":2},{"bubbleId":"t2","type":2},{"bubbleId":"t3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"run the tests"}`),
		toolRow("t1", "run_terminal_command_v2", `{"command":"npm test"}`, "FAIL: 3 failing", ""),
		// The re-run's bubble, recorded argument-less — indistinguishable from a
		// neighbour's argument-less bubble when the run before it was deduped.
		toolRow("t2", "run_terminal_command_v2", `{}`, "PASS all tests passed", ""),
		toolRow("t3", "run_terminal_command_v2", `{}`, " M internal/config/resolve.go", ""),
	})

	d := successfulObject(t, run(t, db, unit(t, transcript)))
	lines := decode(t, d.Payload)

	// Under one reading t2 is the re-run's own bubble, under the other a different call's,
	// and no local signal picks between them.
	assert.NotContains(t, lines[2], "_enrich", "the re-run is undecidable")
	// And the undecided bubble does not cascade: git status gets ITS OWN bubble, not the
	// re-run's declined one.
	e := matchedBubbles(t, lines[3], "t3")[0]
	assert.Truef(t, e["result"] == " M internal/config/resolve.go", "git status result = %v", e["result"])
	// The re-run's likely result must not surface on ANY block.
	assert.NotContains(t, string(d.Payload), "PASS all tests passed", "the declined bubble's result reached the derived object on some other block")
}

// Repeat detection is not bounded by the look-behind window: it consumes nothing, so the
// misplacement the window guards against cannot happen. Bounded, one filler call decided whether
// the same shape was a benign repeat or a discarded conversation.
func TestAStoreDedupedReRunFarBackIsStillARepeat(t *testing.T) {
	var blocks []string
	blocks = append(blocks, `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\naudit everything\n</user_query>"}]}}`)
	blocks = append(blocks, `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}`)
	headers := []string{`{"bubbleId":"b1","type":1}`, `{"bubbleId":"grep","type":2}`}
	rows := []storeRow{
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"audit everything"}`),
		toolRow("grep", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`,
			"etag.go:9", ""),
	}
	// 64 distinct consumed bubbles between the original and its re-run: one past the
	// look-behind bound.
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("fill%02d", i)
		blocks = append(blocks, fmt.Sprintf(`{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"sym%02dAlpha|sym%02dBeta","path":"/work/api/pkg%02d"}}]}}`, i, i, i))
		headers = append(headers, fmt.Sprintf(`{"bubbleId":%q,"type":2}`, id))
		rows = append(rows, bubbleRow(id, fmt.Sprintf(`{"bubbleId":%q,"type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_%s","name":"ripgrep_raw_search",
					"status":"completed","rawArgs":"{\"pattern\":\"sym%02dAlpha|sym%02dBeta\",\"path\":\"/work/api/pkg%02d\"}",
					"result":"pkg%02d.go:1"}}`, id, id, i, i, i, i)))
	}
	// The re-run the store deduped, then real prose with a real bubble, so the re-run
	// cannot ride out on the tail rule.
	blocks = append(blocks, `{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}`)
	blocks = append(blocks, `{"role":"assistant","message":{"content":[{"type":"text","text":"All checks passed."}]}}`)
	headers = append(headers, `{"bubbleId":"a1","type":2}`)
	rows = append(rows,
		bubbleRow("a1", `{"bubbleId":"a1","type":2,"text":"All checks passed."}`),
		composerAt(1755500000000, "["+strings.Join(headers, ",")+"]"))

	res := run(t, newStore(t, rows), unit(t, strings.Join(blocks, "\n")+"\n"))

	successfulObject(t, res)
	assert.Contains(t, strings.Join(res.Infos, " "), "repeat")
}

// A repeat verdict must survey the whole store first: when the re-run's own bubble exists but
// sits past the forward window, the store did record the run and the loud outcome stands.
func TestARepeatWhoseOwnBubbleIsOutOfReachIsAMismatchNotARepeat(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncheck the resolver twice\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/work/api/internal/config/resolve.go"}}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"The resolver is bounded."}]}}
`
	headers := []string{`{"bubbleId":"b1","type":1}`, `{"bubbleId":"r1","type":2}`, `{"bubbleId":"prose","type":2}`}
	rows := []storeRow{
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"check the resolver twice"}`),
		toolRow("r1", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`, "package config", ""),
		bubbleRow("prose", `{"bubbleId":"prose","type":2,"text":"The resolver is bounded."}`),
	}
	// Store-only bubbles a subagent left behind: the transcript never mentions them, and
	// they push the re-run's own bubble past the forward window.
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("sub%02d", i)
		headers = append(headers, fmt.Sprintf(`{"bubbleId":%q,"type":2}`, id))
		rows = append(rows, bubbleRow(id, fmt.Sprintf(`{"bubbleId":%q,"type":2,"capabilityType":15,
				"toolFormerData":{"toolCallId":"call_%s","name":"read_file_v2",
					"status":"completed","rawArgs":"{\"path\":\"/work/api/sub/f%02d.go\"}",
					"result":"subagent detail"}}`, id, id, i)))
	}
	headers = append(headers, `{"bubbleId":"r2","type":2}`)
	rows = append(rows,
		toolRow("r2", "read_file_v2", `{"path":"/work/api/internal/config/resolve.go"}`,
			"package config, again", ""),
		composerAt(1755500000000, "["+strings.Join(headers, ",")+"]"))

	res := run(t, newStore(t, rows), unit(t, transcript))
	require.Equal(t, 1, res.Mismatched)
	require.Lenf(t, res.Objects, 0, "shipped an object claiming a dedup the store contradicts: %v", res.Infos)
}

// A trailing repeat proves nothing about the events before it: Cursor's injected notification
// turns get no bubble, so stamping a watermark there turns a fully explained tail into a mismatch.
func TestATrailingRepeatDoesNotTurnInjectedTurnsIntoMismatches(t *testing.T) {
	transcript := `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\nfind the etag helpers\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"type":"turn_ended","status":"success"}
{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Monday, Aug 3, 2026, 9:05 AM (UTC+2)</timestamp>\n\n<user_query>Briefly inform the user about the task result.</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}}]}}
{"type":"turn_ended","status":"success"}
`
	db := newStore(t, []storeRow{
		composerAt(1755500000000, `[{"bubbleId":"u1","type":1},{"bubbleId":"grep","type":2}]`),
		bubbleRow("u1", `{"bubbleId":"u1","type":1,"text":"find the etag helpers"}`),
		toolRow("grep", "ripgrep_raw_search", `{"pattern":"quoteETag|normaliseETag","path":"/work/api/internal/backends/s3"}`,
			"etag.go:9", ""),
	})

	res := run(t, db, unit(t, transcript))

	successfulObject(t, res)
	joined := strings.Join(res.Infos, " ")
	assert.Contains(t, joined, "extend past the store")
	assert.Contains(t, joined, "repeat")
}
