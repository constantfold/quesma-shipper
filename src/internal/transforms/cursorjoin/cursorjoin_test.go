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
}

// A DB-side-only update: the transcript is byte-identical, so only the output hash can signal it.
func TestAChangedStoreChangesTheOutputHash(t *testing.T) {
	before := successfulObject(t, run(t, fullRows(), transcript))
	after := successfulObject(t, run(t, lsRows(`"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
		"status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"total 24\nA LATE RESULT ARRIVED"}`), transcript))
	assert.NotEqual(t, after.OutputHash, before.OutputHash, "a DB-side-only change would never ship")
	assert.Contains(t, string(after.Payload), "A LATE RESULT ARRIVED")
}

// No database is not an error, and an unreadable one fails open with a count.
func TestAMissingOrUnreadableDatabaseFailsOpen(t *testing.T) {
	res := enrichAt(t, "", transcript)
	assert.Equal(t, transforms.EnrichResult{EnricherID: "cursor-transcript-join", Version: 4, Skipped: 1,
		Notes: []string{"no state.vscdb found: raw transcripts only"}}, res)

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
