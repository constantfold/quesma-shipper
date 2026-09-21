package transforms_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// These use the package's own newScrubber, which is what the engine builds.

const plantedAWSKey = "AKIAIOSFODNN7EXAMPLE"

// Three ways a line could be parsed and still not be scanned, each of which shipped the planted
// key in the clear with an empty ledger. "Parsed" must mean "covered": a walker that understands
// part of a line and reports success is how a redactor fails open.
func TestALineIsEitherFullyCoveredOrRawScanned(t *testing.T) {
	s := newScrubber(t)

	for _, tc := range []struct {
		name, line, wantMode string
	}{
		{
			// A bare string root fell through the walker while the caller still reported the line parsed, so
			// the raw-text fallback never ran either.
			name: "a bare string is the whole record",
			line: `"` + plantedAWSKey + `"`, wantMode: transforms.ScanModeDecodedJSON,
		},
		{
			// The token walk visits every occurrence, so repeated keys are both covered and both retained.
			name: "an object repeats a key",
			line: `{"a":"` + plantedAWSKey + `","a":"kept"}`, wantMode: transforms.ScanModeDecodedJSON,
		},
		{
			// printenv and `kubectl get secret -o yaml` both put the name in key position.
			name: "the secret is in key position",
			line: `{"` + plantedAWSKey + `":"value"}`, wantMode: transforms.ScanModeDecodedJSON,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Scrub([]byte(tc.line+"\n"), transforms.Hint{Family: "claude-code", JSONL: true})
			require.NoError(t, err)
			assert.NotContainsf(t, string(res.Out), plantedAWSKey, "the planted key shipped in the clear:\n%s", res.Out)
			assert.NotEqual(t, 0, res.RuleHits["aws-access-key-id"])
			assert.Equal(t, res.ScanMode, tc.wantMode)
		})
	}
}

// The shadowed value must still be THERE: dropping it would mutate the record, and a reader
// comparing a re-shipped file against its source would see a field vanish for no stated reason.
func TestARepeatedKeyKeepsBothValues(t *testing.T) {
	s := newScrubber(t)
	const line = `{"a":"` + plantedAWSKey + `","a":"kept","b":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`

	res, err := s.Scrub([]byte(line+"\n"), transforms.Hint{Family: "claude-code", JSONL: true})
	require.NoError(t, err)
	out := string(res.Out)
	assert.Equalf(t, 2, strings.Count(out, `"a":`), "the repeated key lost a value:\n%s", out)
	assert.Containsf(t, out, `"a":"kept"`, "the surviving value was altered:\n%s", out)
	for _, rule := range []string{"aws-access-key-id", "github-pat"} {
		assert.NotEqual(t, 0, res.RuleHits[rule])
	}
}

// Ordinary lines must not be pushed onto the raw-text path: it is a fallback, and a payload that
// quietly stopped being parsed would lose the exemptions and the key-name rule with it.
func TestOrdinaryLinesStayOnTheParsedPath(t *testing.T) {
	s := newScrubber(t)
	const line = `{"type":"assistant","uuid":"a1","message":{"content":[{"type":"text","text":"hello"}],` +
		`"usage":{"input_tokens":120}},"toolUseId":"toolu_01FcSqsnNxWeeDGKyfZKjJHbXk9QwErTyU"}`

	res, err := s.Scrub([]byte(line+"\n"), transforms.Hint{Family: "claude-code", JSONL: true})
	require.NoError(t, err)
	assert.Equalf(t, transforms.ScanModeDecodedJSON, res.ScanMode, "scan_mode %q, want %q", res.ScanMode, transforms.ScanModeDecodedJSON)
	assert.Equalf(t, line+"\n", string(res.Out), "an ordinary line was altered:\n got %s\nwant %s", res.Out, line)
}
