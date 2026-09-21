package cursorjoin_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

// THE JOIN. What the transcript cannot say, the derived object does.
func TestTheJoinCarriesTheFieldsTheTranscriptLacks(t *testing.T) {
	res := run(t, fullStore(t), unit(t, transcript))

	require.Equalf(t, 0, res.Mismatched, "the happy path mismatched: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "expected 1 derived object, got %d: %v", len(res.Objects), res.Notes)
	d := res.Objects[0]
	require.Equalf(t, transforms.StatusOK, d.Status, "status = %s", d.Status)
	assert.Truef(t, strings.HasSuffix(d.NativePath, conv+".jsonl.enriched.jsonl"), "derived path = %s", d.NativePath)

	lines := decode(t, d.Payload)
	require.Lenf(t, lines, 3, "derived %d lines, want 3 (one per transcript line)", len(lines))

	// The assistant turn: block 0 is prose, block 1 is the tool call.
	blocks, ok := lines[1]["_enrich"].([]any)
	if !ok || len(blocks) != 2 {
		t.Fatalf("assistant line has no per-block enrichment: %v", lines[1]["_enrich"])
	}
	tool, ok := blocks[1].(map[string]any)
	if !ok {
		t.Fatalf("the tool_use block was not enriched: %v", blocks[1])
	}

	// The four fields the raw transcript structurally cannot carry.
	assert.Truef(t, tool["tool_call_id"] == "call_abc123", "tool_call_id = %v", tool["tool_call_id"])
	assert.Truef(t, tool["status"] == "completed", "status = %v", tool["status"])
	assert.Truef(t, tool["tool_name"] == "run_terminal_cmd", "tool_name = %v (the INTERNAL name, not the transcript's display name)", tool["tool_name"])
	if s, _ := tool["result"].(string); !strings.Contains(s, "main.go") {
		t.Errorf("the tool result did not make it into the derived object: %v", tool["result"])
	}
	// A real timestamp, where the transcript's only time signal is prose in a user message.
	assert.Truef(t, tool["createdAt"] == "2026-07-28T10:06:02.000Z", "createdAt = %v", tool["createdAt"])
}

// The native lines survive byte-for-byte.
func TestTheNativeTranscriptIsPreservedVerbatim(t *testing.T) {
	res := run(t, fullStore(t), unit(t, transcript))
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)

	want := strings.Split(strings.TrimRight(transcript, "\n"), "\n")
	for i, line := range strings.Split(strings.TrimRight(string(res.Objects[0].Payload), "\n"), "\n") {
		var m struct {
			Native json.RawMessage `json:"native"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		// Byte-identical, not merely equivalent: downstream verifies the derived object
		// against the raw file.
		assert.Equalf(t, want[i], string(m.Native), "line %d was re-encoded:\n got %s\nwant %s", i, m.Native, want[i])
	}
}

func TestDerivedFromNamesTheRawInput(t *testing.T) {
	u := unit(t, transcript)
	res := run(t, fullStore(t), u)
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	d := res.Objects[0]
	// Without the pairing, a derived object is an assertion nobody can check.
	if len(d.DerivedFrom) != 1 || d.DerivedFrom[0] != u.SourceHash {
		t.Errorf("derived_from = %v, want [%s]", d.DerivedFrom, u.SourceHash)
	}
	assert.Truef(t, d.DBReadMethod != "" && len(d.DBKeyspaces) != 0 && d.DBRowsRead != 0, "DB provenance is incomplete: method=%q keyspaces=%v rows=%d", d.DBReadMethod, d.DBKeyspaces, d.DBRowsRead)
	// Scope is declared, and the declaration is what the provenance records.
	for _, ks := range d.DBKeyspaces {
		assert.Truef(t, ks == "composerData:" || ks == "bubbleId:", "undeclared keyspace in provenance: %s", ks)
	}
}

// THE DETERMINISM GATE. Same input values, same output bytes.
func TestTheOutputIsByteIdenticalAcrossRuns(t *testing.T) {
	// Two databases with the same rows inserted in a different order. If the output differed,
	// the hash would stop being a change signal and every tick would re-ship everything.
	first := run(t, fullStore(t), unit(t, transcript))
	second := run(t, fullStore(t), unit(t, transcript))

	if len(first.Objects) != 1 || len(second.Objects) != 1 {
		t.Fatalf("expected one object each: %d, %d", len(first.Objects), len(second.Objects))
	}
	assert.Equal(t, string(second.Objects[0].Payload), string(first.Objects[0].Payload), "two runs over identical inputs produced different bytes")
	assert.Equalf(t, second.Objects[0].OutputHash, first.Objects[0].OutputHash, "output hashes differ: %s vs %s", first.Objects[0].OutputHash, second.Objects[0].OutputHash)
}

func TestAChangedStoreChangesTheOutputHash(t *testing.T) {
	before := run(t, fullStore(t), unit(t, transcript))

	// A DB-side-only update: the transcript is byte-identical, so only the output hash can
	// signal that there is something new to ship.
	rows := []storeRow{
		composerRow(`[
				{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
				"name":"run_terminal_cmd","status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}",
				"result":"total 24\nA LATE RESULT ARRIVED"}}`),
	}
	after := run(t, newStore(t, rows), unit(t, transcript))

	if len(before.Objects) != 1 || len(after.Objects) != 1 {
		t.Fatalf("expected one object each: %v / %v", before.Notes, after.Notes)
	}
	assert.NotEqual(t, after.Objects[0].OutputHash, before.Objects[0].OutputHash, "a DB-side-only change did not change the output hash, so it would never ship")
	assert.Contains(t, string(after.Objects[0].Payload), "A LATE RESULT ARRIVED", "the late result is not in the derived object")
}

// No database is not an error.
func TestNoDatabaseMeansSkippedNotFailed(t *testing.T) {
	res := run(t, "", unit(t, transcript))
	assert.Equalf(t, 0, res.Errors, "a missing state.vscdb was counted as an error")
	assert.Equalf(t, 1, res.Skipped, "skipped = %d, want 1", res.Skipped)
	assert.Lenf(t, res.Objects, 0, "derived %d objects with no database", len(res.Objects))
}

// An unreadable database fails open.
func TestAnUnreadableDatabaseFailsOpenWithACount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.vscdb")
	require.NoError(t, os.WriteFile(path, []byte("this is not a database"), 0o600))
	res := run(t, path, unit(t, transcript))

	// Fail open and counted: an unreadable database costs this flush's DB-side fields only.
	assert.Lenf(t, res.Objects, 0, "derived %d objects from an unreadable database", len(res.Objects))
	assert.Equalf(t, 1, res.Errors, "errors = %d, want 1", res.Errors)
	assert.NotEqual(t, 0, len(res.Notes), "an unreadable database produced no note")
}

// THE NO-ROWS GATE, at this level: nothing the enricher emits may contain a raw store row.
func TestNoStoreRowReachesTheDerivedObjectWholesale(t *testing.T) {
	// A row field the join does not use must not appear: the derived object is a join of
	// named fields, not a dump, which is where "no rows ship" could be violated.
	rows := []storeRow{
		{
			key: "composerData:" + conv,
			value: fmt.Sprintf(`{"composerId":%q,"UNUSED_MARKER":"must-not-ship",
				"fullConversationHeadersOnly":[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]}`, conv),
		},
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace","ALSO_UNUSED":"must-not-ship"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents."}`),
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"toolFormerData":{"toolCallId":"call_abc123",
				"name":"run_terminal_cmd","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}}`),
	}
	res := run(t, newStore(t, rows), unit(t, transcript))
	require.Lenf(t, res.Objects, 1, "no derived object: %v", res.Notes)
	payload := string(res.Objects[0].Payload)
	for _, marker := range []string{"UNUSED_MARKER", "ALSO_UNUSED", "must-not-ship"} {
		assert.NotContainsf(t, payload, marker, "a store field the join does not use reached the derived object: %s", marker)
	}
}

func TestTheEnricherIsIdentifiedByIDAndVersion(t *testing.T) {
	e := cursorjoin.New()
	// Both travel in every manifest, so a fixed join's output supersedes a broken one's.
	assert.Equalf(t, "cursor-transcript-join", e.ID(), "id = %q", e.ID())
	assert.Equalf(t, 4, e.Version(), "version = %d", e.Version())
	assert.Equalf(t, "cursorDiskKV", e.Table(), "table = %q", e.Table())
	// The workspace state.vscdb is v1.1, deferred. Only the global store is declared.
	for _, c := range e.DBCandidates() {
		assert.NotContainsf(t, c, "workspaceStorage", "the workspace store is declared but deferred to v1.1: %s", c)
		assert.Containsf(t, c, "globalStorage", "candidate is not the global store: %s", c)
	}
}
