package cursorjoin_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

const conv = "5d1f7b3e-9a2c-4e8f-b1d0-3c4a5b6c7d8e"

type storeRow struct {
	key   string
	value string
}

func newStore(t *testing.T, rows []storeRow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.vscdb")

	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)`); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)`, r.key, r.value); err != nil {
			t.Fatalf("insert %s: %v", r.key, err)
		}
	}
	return path
}

// transcript is the raw side: a user turn, an assistant turn with a tool call, a terminator.
const transcript = `{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Tuesday, Jul 28, 2026, 12:06 PM (UTC+2)</timestamp>\n<user_query>\nlist the workspace\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Listing the workspace folder contents."},{"type":"tool_use","name":"Shell","input":{"command":"ls -la /work/api","description":"List files in workspace root"}}]}}
{"type":"turn_ended","status":"success"}
`

// fullStore is the happy path: headers name every bubble, the tool bubble carries the result.
func fullStore(t *testing.T) string {
	t.Helper()
	return newStore(t, []storeRow{
		composerAt(1753700000000, `[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2},{"bubbleId":"b3","type":2}]`),
		bubbleRow("b1", `{"bubbleId":"b1","type":1,"text":"list the workspace",
				"createdAt":"2026-07-28T10:06:00.000Z","requestId":"req-1"}`),
		bubbleRow("b2", `{"bubbleId":"b2","type":2,"text":"Listing the workspace folder contents.",
				"createdAt":"2026-07-28T10:06:01.000Z","requestId":"req-2",
				"modelName":"claude-4.5-sonnet","turnDurationMs":1420,"checkpointId":"ckpt-9"}`),
		// The point of the enricher: the store has the output, the call id, the status.
		bubbleRow("b3", `{"bubbleId":"b3","type":2,"createdAt":"2026-07-28T10:06:02.000Z",
				"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
					"status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}",
					"result":"total 24\ndrwxr-xr-x  5 jane staff  160 Jul 28 10:05 .\n-rw-r--r--  1 jane staff  812 Jul 28 09:58 main.go"}}`),
	})
}

func unit(t *testing.T, body string) transforms.RawUnit {
	t.Helper()
	return transforms.RawUnit{
		NativePath: "/Users/jane/.cursor/projects/api/agent-transcripts/" + conv + ".jsonl",
		Content:    []byte(body),
		SourceHash: transforms.Hash([]byte(body)),
	}
}

func run(t *testing.T, dbPath string, units ...transforms.RawUnit) transforms.EnrichResult {
	t.Helper()
	return cursorjoin.New().Enrich(transforms.Input{
		Units:      units,
		DBPath:     dbPath,
		ScratchDir: filepath.Join(t.TempDir(), "scratch"),
	})
}

// decode reads the derived JSONL back.
func decode(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(payload), "\n"), "\n") {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		out = append(out, m)
	}
	return out
}

func composerRow(headers string) storeRow {
	return storeRow{"composerData:" + conv, fmt.Sprintf(`{"composerId":%q,"fullConversationHeadersOnly":%s}`, conv, headers)}
}

func bubbleRow(id, body string) storeRow {
	return storeRow{"bubbleId:" + conv + ":" + id, body}
}

func composerAt(createdAt int64, headers string) storeRow {
	return storeRow{"composerData:" + conv, fmt.Sprintf(`{"composerId":%q,"createdAt":%d,"fullConversationHeadersOnly":%s}`, conv, createdAt, headers)}
}

func joined(t *testing.T, db, transcript string) []map[string]any {
	t.Helper()
	d := successfulObject(t, run(t, db, unit(t, transcript)))
	return decode(t, d.Payload)
}

// Completed calls use Cursor's standard bubble envelope.
func toolRow(id, name, args, result, at string) storeRow {
	body := map[string]any{
		"bubbleId": id, "type": 2, "capabilityType": 15,
		"toolFormerData": map[string]string{
			"toolCallId": "call_" + id, "name": name, "status": "completed",
			"rawArgs": args, "result": result,
		},
	}
	if at != "" {
		body["createdAt"] = at
	}
	encoded, _ := json.Marshal(body)
	return bubbleRow(id, string(encoded))
}

func matchedBubbles(t *testing.T, line map[string]any, ids ...string) []map[string]any {
	t.Helper()
	items, _ := line["_enrich"].([]any)
	require.Len(t, items, len(ids))
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i], _ = item.(map[string]any)
		require.NotNil(t, out[i], "block %d", i)
		assert.Equal(t, ids[i], out[i]["bubbleId"], "block %d", i)
	}
	return out
}

func successfulObject(t *testing.T, res transforms.EnrichResult) transforms.Derived {
	t.Helper()
	require.Zerof(t, res.Mismatched, "mismatch notes: %v", res.Notes)
	require.Lenf(t, res.Objects, 1, "derived object missing: %v", res.Notes)
	return res.Objects[0]
}
