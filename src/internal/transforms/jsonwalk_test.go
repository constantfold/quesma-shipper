package transforms

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
)

func sourcePatchScrubber(t *testing.T) *Scrubber {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Exemptions = CompiledExemptions()
	cfg.Username = "jane"
	s, err := New(cfg)
	require.NoError(t, err)
	return s
}

func TestJSONTextAcceptanceMatchesEncodingJSON(t *testing.T) {
	s := sourcePatchScrubber(t)
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

func TestSourcePatchingRequotesOnlyDirtyStrings(t *testing.T) {
	s := sourcePatchScrubber(t)
	before := " \t{ \"n\" : 1e+09, \"text\" : \"left\\/\\u003c AKI\\u0041IOSFODNN7EXAMPLE right\", \"keep\":\"\\u0041\\/\" } \r\n"
	want := " \t{ \"n\" : 1e+09, \"text\" : \"left/< __REDACTED:aws-access-key-id__ right\", \"keep\":\"\\u0041\\/\" } \r\n"

	res, err := s.Scrub([]byte(before), Hint{Family: "claude-code", JSONL: true})
	require.NoError(t, err)
	require.Equal(t, string(res.Out), want)
	require.Truef(t, res.ScanMode == ScanModeDecodedJSON && res.RuleHits["aws-access-key-id"] == 1, "unexpected result metadata: %+v", res)
}

func TestSourcePatchingCoversKeysDuplicatesAndBareStrings(t *testing.T) {
	s := sourcePatchScrubber(t)
	for _, tc := range []struct {
		name, before, want string
	}{
		{
			name:   "escaped key",
			before: `{"AKI\u0041IOSFODNN7EXAMPLE":"kept"}`,
			want:   `{"__REDACTED:aws-access-key-id__":"kept"}`,
		},
		{
			name:   "duplicate values",
			before: `{"a":"AKIAIOSFODNN7EXAMPLE","a":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`,
			want:   `{"a":"__REDACTED:aws-access-key-id__","a":"__REDACTED:github-pat__"}`,
		},
		{
			name:   "leading whitespace before bare string",
			before: `  "AKI\u0041IOSFODNN7EXAMPLE" `,
			want:   `  "__REDACTED:aws-access-key-id__" `,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Scrub([]byte(tc.before), Hint{Family: "claude-code", JSONL: true})
			require.NoError(t, err)
			require.Equal(t, string(res.Out), tc.want)
			require.Equalf(t, ScanModeDecodedJSON, res.ScanMode, "scan mode = %q", res.ScanMode)
		})
	}
}

func TestSourcePatchingNormalizesExceptionalBytesInDirtyStrings(t *testing.T) {
	s := sourcePatchScrubber(t)
	for _, tc := range []struct{ name, prefix string }{{"invalid UTF-8", "\xff"}, {"unpaired surrogate", `\ud800`}} {
		t.Run(tc.name, func(t *testing.T) {
			before := `{"text":"` + tc.prefix + ` / AKIAIOSFODNN7EXAMPLE / \u0041"}`
			want := `{"text":"� / __REDACTED:aws-access-key-id__ / A"}`
			res, err := s.Scrub([]byte(before), Hint{Family: "claude-code", JSONL: true})
			require.NoError(t, err)
			require.Equal(t, string(res.Out), want)
		})
	}
}
