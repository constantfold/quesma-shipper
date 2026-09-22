package transforms

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

func TestJSONTextAcceptanceMatchesEncodingJSON(t *testing.T) {
	s := newScrubber(t)
	for _, line := range []string{
		`null`, `true`, `-0`, `1e+9`, `"text"`, `[]`, `{}`,
		` { "a" : [1, {"b":"x"}], "a": 2 } `,
		`"\"\\\/\b\f\n\r\t\u0041\ud83d\ude00\ud800"`,
		"\"a\xffb\"",
		``, ` `, `{`, `[1,]`, `{"a":}`, `01`, `+1`, `.1`, `NaN`,
		`true false`, `"\q"`, "\"\n\"", `{"a":1,}`,
	} {
		var scan packs.ValueScan
		var walker jsonWalker
		walker.reset(s, "claude-code", &scan, []byte(line))
		got := walker.walkLine() == nil
		assert.Equal(t, got, json.Valid([]byte(line)))
	}
}

// Only a changed string is requoted, minimally; every other byte, escapes included, ships as it came.
func TestSourcePatchingRequotesOnlyDirtyStrings(t *testing.T) {
	s := newScrubber(t)
	for _, tc := range []struct{ name, before, want string }{
		{
			"escapes and whitespace",
			" \t{ \"n\" : 1e+09, \"text\" : \"left\\/\\u003c AKI\\u0041IOSFODNN7EXAMPLE right\", \"keep\":\"\\u0041\\/\" } \r\n",
			" \t{ \"n\" : 1e+09, \"text\" : \"left/< __REDACTED:aws-access-key-id__ right\", \"keep\":\"\\u0041\\/\" } \r\n",
		},
		{"escaped key", `{"AKI\u0041IOSFODNN7EXAMPLE":"kept"}`, `{"__REDACTED:aws-access-key-id__":"kept"}`},
		{
			"duplicate values",
			`{"a":"AKIAIOSFODNN7EXAMPLE","a":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`,
			`{"a":"__REDACTED:aws-access-key-id__","a":"__REDACTED:github-pat__"}`,
		},
		{"bare string after whitespace", `  "AKI\u0041IOSFODNN7EXAMPLE" `, `  "__REDACTED:aws-access-key-id__" `},
		{"invalid UTF-8", `{"text":"` + "\xff" + ` / AKIAIOSFODNN7EXAMPLE / \u0041"}`, `{"text":"� / __REDACTED:aws-access-key-id__ / A"}`},
		{"unpaired surrogate", `{"text":"\ud800 / AKIAIOSFODNN7EXAMPLE / \u0041"}`, `{"text":"� / __REDACTED:aws-access-key-id__ / A"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Scrub([]byte(tc.before), Hint{Family: "claude-code", JSONL: true})
			require.NoError(t, err)
			require.Equal(t, tc.want, string(res.Out))
			require.Equal(t, ScanModeDecodedJSON, res.ScanMode)
			require.Equal(t, 1, res.RuleHits["aws-access-key-id"])
		})
	}
}
