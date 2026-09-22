package cursorjoin_test

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/cursorjoin"
)

const conv = "5d1f7b3e-9a2c-4e8f-b1d0-3c4a5b6c7d8e"

type storeRow struct{ key, value string }

func newStore(t *testing.T, rows []storeRow) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.vscdb")
	db, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)`)
	require.NoError(t, err)
	for _, r := range rows {
		_, err := db.Exec(`INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)`, r.key, r.value)
		require.NoError(t, err, r.key)
	}
	return path
}

// transcript is the raw side: a user turn, an assistant turn with a tool call, a terminator.
const transcript = `{"role":"user","message":{"content":[{"type":"text","text":"<timestamp>Tuesday, Jul 28, 2026, 12:06 PM (UTC+2)</timestamp>\n<user_query>\nlist the workspace\n</user_query>"}]}}
{"role":"assistant","message":{"content":[{"type":"text","text":"Listing the workspace folder contents."},{"type":"tool_use","name":"Shell","input":{"command":"ls -la /work/api","description":"List files in workspace root"}}]}}
{"type":"turn_ended","status":"success"}
`

// fullRows is the happy path for transcript: headers name every bubble, the tool bubble carries the result.
func fullRows() []storeRow {
	return conversation(
		bubbleRow("b1", `{"type":1,"text":"list the workspace","createdAt":"2026-07-28T10:06:00.000Z","requestId":"req-1"}`),
		bubbleRow("b2", `{"type":2,"text":"Listing the workspace folder contents.","createdAt":"2026-07-28T10:06:01.000Z",
			"requestId":"req-2","modelName":"claude-4.5-sonnet","turnDurationMs":1420,"checkpointId":"ckpt-9"}`),
		lsBubble(`"createdAt":"2026-07-28T10:06:02.000Z","toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd",
			"status":"completed","rawArgs":"{\"command\":\"ls -la /work/api\"}",
			"result":"total 24\ndrwxr-xr-x  5 jane staff  160 Jul 28 10:05 .\n-rw-r--r--  1 jane staff  812 Jul 28 09:58 main.go"}`),
	)
}

// lsRows is transcript's store with the fields of its tool bubble b3 supplied by the caller.
func lsRows(toolFields string) []storeRow {
	return conversation(user("b1", "list the workspace"), said("b2", "Listing the workspace folder contents."), lsBubble(toolFields))
}

// lsTool is the plainest tool bubble transcript's ls call aligns to.
const lsTool = `"toolFormerData":{"toolCallId":"call_abc123","name":"run_terminal_cmd","rawArgs":"{\"command\":\"ls -la /work/api\"}","result":"ok"}`

func lsBubble(fields string) storeRow { return bubbleRow("b3", `{"type":2,`+fields+`}`) }

func unit(body string) transforms.RawUnit {
	return transforms.RawUnit{
		NativePath: "/Users/jane/.cursor/projects/api/agent-transcripts/" + conv + ".jsonl",
		Content:    []byte(body),
		SourceHash: transforms.Hash([]byte(body)),
	}
}

func run(t *testing.T, rows []storeRow, body string) transforms.EnrichResult {
	t.Helper()
	return enrichAt(t, newStore(t, rows), body)
}

func enrichAt(t *testing.T, dbPath, body string) transforms.EnrichResult {
	return cursorjoin.New().Enrich(transforms.Input{
		Units:      []transforms.RawUnit{unit(body)},
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

// conversation is a composer whose header order is the order of the bubbles, then the bubbles.
func conversation(bubbles ...storeRow) []storeRow {
	headers := make([]string, len(bubbles))
	for i, b := range bubbles {
		headers[i] = fmt.Sprintf(`{"bubbleId":%q}`, b.key[strings.LastIndex(b.key, ":")+1:])
	}
	composer := fmt.Sprintf(`{"composerId":%q,"fullConversationHeadersOnly":[%s]}`, conv, strings.Join(headers, ","))
	return append([]storeRow{{"composerData:" + conv, composer}}, bubbles...)
}

// bubbleRow stores body under id; the join takes the bubble id from the key.
func bubbleRow(id, body string) storeRow { return storeRow{"bubbleId:" + conv + ":" + id, body} }

func user(id, text string) storeRow { return prose(id, 1, text) }
func said(id, text string) storeRow { return prose(id, 2, text) }

func prose(id string, typ int, text string) storeRow {
	body, _ := json.Marshal(map[string]any{"type": typ, "text": text})
	return bubbleRow(id, string(body))
}

// tool is a tool bubble in Cursor's standard envelope; status defaults to completed.
type tool struct{ id, name, rawArgs, params, status, result string }

func (tl tool) row() storeRow {
	body, _ := json.Marshal(map[string]any{
		"type": 2, "capabilityType": 15,
		"toolFormerData": map[string]string{
			"toolCallId": "call_" + tl.id, "name": tl.name, "status": cmp.Or(tl.status, "completed"),
			"rawArgs": tl.rawArgs, "params": tl.params, "result": tl.result,
		},
	})
	return bubbleRow(tl.id, string(body))
}

func toolRow(id, name, rawArgs, result string) storeRow {
	return tool{id: id, name: name, rawArgs: rawArgs, result: result}.row()
}

// matchedBubbles asserts the bubble each block of line joined to, "" for a block with none.
func matchedBubbles(t *testing.T, line map[string]any, ids ...string) []map[string]any {
	t.Helper()
	items, _ := line["_enrich"].([]any)
	require.Len(t, items, len(ids))
	out := make([]map[string]any, len(items))
	for i, item := range items {
		out[i], _ = item.(map[string]any)
		if ids[i] == "" {
			assert.Nil(t, item, "block %d", i)
			continue
		}
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

// joinCase is one conversation through the enricher. A query prepends that user turn to the
// transcript and its bubble b1 to the bubbles; rows, when set, replace conversation(bubbles).
type joinCase struct {
	name       string
	query      string
	transcript string // JSONL; the shared transcript when empty
	bubbles    []storeRow
	rows       []storeRow
	want       map[int][]string // transcript line -> the bubble each block joined to, "" for none
	present    []string         // must appear in the derived object
	absent     []string         // must appear nowhere in the derived object
	infos      []string         // must appear in the object's infos
	mismatch   bool             // no object, one mismatch alarm
}

func runJoinCases(t *testing.T, cases []joinCase) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := cmp.Or(tc.transcript, transcript)
			if tc.query != "" {
				body = `{"role":"user","message":{"content":[{"type":"text","text":"<user_query>\n` + tc.query + `\n</user_query>"}]}}` + "\n" + body
				tc.bubbles = append([]storeRow{user("b1", tc.query)}, tc.bubbles...)
			}
			if tc.rows == nil {
				tc.rows = conversation(tc.bubbles...)
			}
			res := run(t, tc.rows, strings.TrimRight(body, "\n")+"\n")
			if tc.mismatch {
				require.Equalf(t, 1, res.Mismatched, "notes: %v", res.Notes)
				require.Emptyf(t, res.Objects, "infos: %v", res.Infos)
				assert.Contains(t, strings.Join(res.Notes, " "), "raw transcript ships", "the alarm must say the raw file is unaffected")
				return
			}
			for _, n := range res.Notes {
				require.NotContains(t, n, "did not decode")
			}
			d := successfulObject(t, res)
			lines := decode(t, d.Payload)
			for i, ids := range tc.want {
				matchedBubbles(t, lines[i], ids...)
			}
			for _, s := range tc.present {
				assert.Contains(t, string(d.Payload), s)
			}
			for _, s := range tc.absent {
				assert.NotContains(t, string(d.Payload), s)
			}
			for _, s := range tc.infos {
				assert.Contains(t, strings.Join(res.Infos, " "), s)
			}
		})
	}
}

func jsonl(lines ...string) string { return strings.Join(lines, "\n") }

// turn is one assistant transcript line holding the given blocks.
func turn(blocks ...string) string {
	return `{"role":"assistant","message":{"content":[` + strings.Join(blocks, ",") + `]}}`
}

func use(name, input string) string {
	return `{"type":"tool_use","name":"` + name + `","input":` + input + `}`
}

func text(s string) string {
	b, _ := json.Marshal(map[string]string{"type": "text", "text": s})
	return string(b)
}
