package transforms_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// These records contain no secrets; preserve every byte, including identifiers and prior sentinels.
func TestScrubPreservesCleanRecords(t *testing.T) {
	s := newScrubber(t)
	for _, tc := range []struct{ name, payload string }{
		{"ExemptIdentifiersSurvive",
			`{"type":"assistant","uuid":"9f2c4e10-3b7a-4c19-8f2e-1a2b3c4d5e6f",` +
				`"parentUuid":"1a2b3c4d-5e6f-4718-9a0b-1c2d3e4f5a6b",` +
				`"sessionId":"3f2504e0-4f89-41d3-9a0c-0305e82c3301",` +
				`"requestId":"req_011CQ8xKp3mNvRtY7wZa2bCd",` +
				`"timestamp":"2026-07-30T10:00:00.123Z","version":"2.1.220",` +
				`"message":{"id":"msg_01ABcdEfGhIjKlMnOpQrStUv","content":[{"type":"text","text":"hello"}]}}`},
		{"SubagentMetaJoinKeySurvives",
			`{"agentType":"general-purpose","description":"Audit cache failures","toolUseId":"toolu_0183yENGzL6di289E8QTzyxi","spawnDepth":1}`},
		// Repeating hex has low entropy regardless of length; random blobs have a separate regression.
		{"EntropyBackstopIsBlindToRepeatingStructure",
			`{"type":"user","message":{"content":[{"type":"text","text":"` + strings.Repeat("89504e470d0a1a0a0000000d49484452", 200) + `"}]}}`},
		{"UntouchedRecordsAreByteIdentical",
			`{"type":"user","uuid":"u1","timestamp":"2026-07-30T10:00:00Z","nested":{"b":2,"a":1},` +
				`"big":1234567890123456789,"float":1.5,"esc":"tab\there \"quoted\" <html>","nil":null,"arr":[3,2,1]}`},
		// __USER__ adds entropy to a dash-encoded path, but must never trigger another redaction.
		{"UserPlaceholderNeverTripsTheEntropyBackstop",
			`{"type":"user","uuid":"u1","cwd":"/Users/__USER__/Work2026/SampleOrg/blink-UI",` +
				`"message":{"content":[{"type":"text","text":"logs under ~/.claude/projects/-Users-__USER__-Work2026-SampleOrg-blink-UI/f00.jsonl"}]}}`},
		{"SentinelGlueNeverTripsTheEntropyBackstop",
			`{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"https://www.linkedin.com/posts/john-doe-1234567_acme-fastest-software-company-to-100m-in-activity-__REDACTED:card-pan__-KzYA"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload + "\n"
			res := scrubJSONL(t, s, "claude-code", payload)
			assert.Equal(t, payload, string(res.Out))
			assert.Zero(t, res.BytesRedacted)
			assert.Empty(t, res.RuleHits)
		})
	}
}

// When a record IS modified, key order and number literals must still survive: 1.23e+18
// for a large integer is gratuitous damage to bytes the shipper preserves.
func TestModifiedRecordsPreserveKeyOrderAndNumbers(t *testing.T) {
	s := newScrubber(t)

	payload := `{"zeta":1,"alpha":"ghp_abcdefghijklmnopqrstuvwxyz0123456789","mid":1234567890123456789,"beta":true}` + "\n"
	res := scrubJSONL(t, s, "claude-code", payload)
	out := string(res.Out)

	assert.Truef(t, strings.Index(out, `"zeta"`) <= strings.Index(out, `"alpha"`), "key order was not preserved:\n%s", out)
	assert.Containsf(t, out, "1234567890123456789", "a large integer lost precision:\n%s", out)
	assert.True(t, strings.Contains(out, "<html>") || !strings.Contains(payload, "<html>"), "HTML escaping was applied where the input had none")
}

// The sentinel's width depends only on the rule id, so it cannot leak the secret's
// length, and nothing in it derives from the value.
func TestSentinelLeaksNeitherLengthNorValue(t *testing.T) {
	s := newScrubber(t)

	short := "ghp_" + strings.Repeat("a", 36)
	long := "ghp_" + strings.Repeat("b", 200)

	outShort := scrubJSONL(t, s, "claude-code", `{"t":"`+short+`"}`+"\n")
	outLong := scrubJSONL(t, s, "claude-code", `{"t":"`+long+`"}`+"\n")

	assert.Lenf(t, outShort.Out, len(outLong.Out), "sentinel width tracks the secret length: %d vs %d bytes", len(outShort.Out), len(outLong.Out))
	assert.Containsf(t, string(outShort.Out), transforms.Sentinel("github-pat"), "sentinel should carry the rule id: %s", outShort.Out)
	for _, frag := range []string{"aaaa", "bbbb"} {
		assert.True(t, !strings.Contains(string(outShort.Out), frag) && !strings.Contains(string(outLong.Out), frag), "a fragment of the secret survived in the placeholder")
	}
}

// Idempotence: a second pass must not redact the first pass's placeholders, which would
// destroy the ledger's meaning.
func TestScrubIsIdempotent(t *testing.T) {
	s := newScrubber(t)
	// Deliberately long and mixed-case: the first pass turns "jane" into "__USER__", which
	// ADDS entropy, and the second pass must not eat that.
	payload := `{"type":"user","cwd":"/Users/jane/Work2026/SampleOrg/blink-UI","message":{"content":[{"type":"text","text":"ghp_abcdefghijklmnopqrstuvwxyz0123456789 in ~/.claude/projects/-Users-jane-Work2026-SampleOrg-blink-UI/f00.jsonl"}]}}` + "\n"

	first := scrubJSONL(t, s, "claude-code", payload)
	second := scrubJSONL(t, s, "claude-code", string(first.Out))

	assert.Equalf(t, string(first.Out), string(second.Out), "second pass changed the output:\n first %s\nsecond %s", first.Out, second.Out)
}
