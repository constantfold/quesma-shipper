package transforms_test

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// exemptions is the COMPILED baseline, not a test fixture: testing the same list the
// binary runs is the point.
func exemptions() map[string][]string {
	return transforms.CompiledExemptions()
}

func newScrubber(t *testing.T) *transforms.Scrubber {
	t.Helper()
	cfg := transforms.DefaultConfig()
	cfg.Exemptions = exemptions()
	cfg.Username = "jane"
	s, err := transforms.New(cfg)
	require.NoError(t, err)
	return s
}

func scrubJSONL(t *testing.T, s *transforms.Scrubber, family, payload string) transforms.Result {
	t.Helper()
	res, err := s.Scrub([]byte(payload), transforms.Hint{Family: family, JSONL: true})
	require.NoErrorf(t, err, "scrub returned an engine error: %v", err)
	return res
}

func TestRepresentativeLeaksAreRedacted(t *testing.T) {
	s := newScrubber(t)

	cases := []struct {
		name   string
		secret string
		ruleID string
	}{
		{"github pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github-pat"},
		{"github fine-grained pat", "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP", "github-fine-grained-pat"},
		{"aws access key id", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"openai key", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "openai-api-key"},
		{"anthropic key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", "anthropic-api-key"},
		{"slack bot token", "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", "slack-token"},
		{"stripe live key", "sk_live_abcdefghijklmnopqrstuvwx", "stripe-secret-key"},
		{"google api key", "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456", "google-api-key"},
		{"npm token", "npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm-token"},
		{"gitlab pat", "glpat-abcdefghijklmnopqrst", "gitlab-pat"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "jwt"},
		{"digitalocean pat", "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "digitalocean-token"},
		{"huggingface token", "hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh", "huggingface-access-token"},
		{"vault service token", "hvs.CAESIJ0123456789abcdefghijklmnopqrstuvwxyz", "vault-token"},
		{"age secret key", "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE", "age-secret-key"},
		{"groq key", "gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "groq-api-key"},
		{"xai key", "xai-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqr", "xai-api-key"},
		{"perplexity key", "pplx-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", "perplexity-api-key"},
		{"dockerhub pat", "dckr_pat_abcdefghijklmnopqrstuvwxyzA", "dockerhub-token"},
		{"tailscale key", "tskey-auth-kFGiAS7CNTRL-abcdefghijklmnopqrstuv", "tailscale-key"},
		{"gitlab runner token", "glrt-abcdefghijklmnopqrst0", "gitlab-token-family"},
		{"stripe webhook secret", "whsec_abcdefghijklmnopqrstuvwxyzABCDEF", "stripe-webhook-secret"},
		{"atlassian api token", "ATATT3" + strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3), "atlassian-api-token"},
		{"azure ad client secret", "abc8Q~dEfGhIjKlMnOpQrStUvWxYz0123456789~", "azure-ad-client-secret"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := `{"type":"user","message":{"content":[{"type":"text","text":"the key is ` + c.secret + ` ok"}]}}`
			res := scrubJSONL(t, s, "claude-code", line+"\n")

			assert.NotContainsf(t, string(res.Out), c.secret, "secret survived:\n%s", res.Out)
			assert.NotEqual(t, 0, res.RuleHits[c.ruleID])
			assert.Containsf(t, string(res.Out), "__REDACTED:", "no sentinel in output:\n%s", res.Out)
		})
	}
}

// The aws CLI labels the secret "SecretAccessKey", with no "aws" anywhere near it, and
// tool output reaches transcripts as JSON-in-string where key-name scrubbing cannot see
// the field. The whole value must go: a secret containing "/" must not survive as
// fragments around the entropy tokenizer's split points.
func TestAWSCliCredentialOutputIsFullyRedacted(t *testing.T) {
	s := newScrubber(t)
	const keyID = "AKIAIOSFODNN7EXAMPLE"
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	cases := []struct {
		name   string
		text   string
		ruleID string
	}{
		{"create-access-key tool output", `{\"AccessKey\": {\"UserName\": \"ingest\", \"AccessKeyId\": \"` + keyID + `\", \"SecretAccessKey\": \"` + secret + `\", \"Status\": \"Active\"}}`, "secret-access-key"},
		{"yaml-style label", "SecretAccessKey: " + secret, "secret-access-key"},
		{"env-style with aws prefix", "aws_secret_access_key = " + secret, "aws-secret-key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := `{"type":"user","message":{"content":[{"type":"tool_result","content":"` + c.text + `"}]}}`
			res := scrubJSONL(t, s, "claude-code", line+"\n")
			out := string(res.Out)
			assert.NotContainsf(t, out, secret, "secret survived:\n%s", out)
			assert.NotContainsf(t, out, "wJalrXUtnFEMI", "secret fragment survived:\n%s", out)
			assert.NotEqual(t, 0, res.RuleHits[c.ruleID])
			assert.NotContainsf(t, out, keyID, "access key id survived:\n%s", out)
		})
	}
}

// A PEM block spans lines inside one JSON string value, the shape a byte-level regex
// over the raw file would mangle.
func TestPrivateKeyBlockIsRedacted(t *testing.T) {
	s := newScrubber(t)
	pem := "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA3x2n\\n-----END RSA PRIVATE KEY-----"
	line := `{"type":"user","message":{"content":[{"type":"text","text":"` + pem + `"}]}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	assert.NotContainsf(t, string(res.Out), "MIIEowIBAAKCAQEA3x2n", "key body survived:\n%s", res.Out)
	assert.NotEqual(t, 0, res.RuleHits["private-key-block"])
}

// printenv and kubectl output: the value has no recognisable shape but the key does,
// and only the value goes.
func TestKeyNameRulesCatchShapelessValues(t *testing.T) {
	s := newScrubber(t)

	cases := []string{
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"DATABASE_URL=postgres://app:hunter2@db.internal:5432/prod",
		"MY_SERVICE_TOKEN=plain-looking-value-1234",
		"ACME_PASSWORD: correct-horse-battery",
		"internal_secret = abcdefghijklmno",
	}
	for _, env := range cases {
		t.Run(env, func(t *testing.T) {
			line := `{"type":"user","toolUseResult":{"stdout":"` + env + `"}}`
			res := scrubJSONL(t, s, "claude-code", line+"\n")
			out := string(res.Out)

			name := env[:strings.IndexAny(env, "=:")]
			name = strings.TrimSpace(name)
			assert.Containsf(t, out, name, "the key name should survive — it is useful signal and not the secret:\n%s", out)
			assert.Containsf(t, out, "__REDACTED:", "the value was not redacted:\n%s", out)
		})
	}
}

// A planted secret in EVERY structurally exempt field is still caught, which is only
// satisfiable because exemptions are detector-scoped: the pattern packs scan every
// field regardless.
func TestPlantedSecretInEveryExemptFieldIsStillCaught(t *testing.T) {
	s := newScrubber(t)
	const planted = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

	for family, paths := range exemptions() {
		for _, path := range paths {
			t.Run(family+"/"+path, func(t *testing.T) {
				line := buildRecordWithValueAt(t, path, planted)
				fam := family
				if fam == "*" {
					fam = "claude-code"
				}
				res := scrubJSONL(t, s, fam, line+"\n")

				assert.NotContainsf(t, string(res.Out), planted, "a planted secret survived in exempt field %q:\n%s", path, res.Out)
			})
		}
	}
}

// A redacted multi-record trajectory still reassembles: the join keys are what make a
// DAG out of a line-oriented file.
func TestGraphReassemblesAfterScrub(t *testing.T) {
	s := newScrubber(t)

	// The id must stay production-length: below the backstop's 24-char floor it passed
	// with an EMPTY exemption set while real archives shipped every tool_use id redacted.
	const toolUseID = "toolu_0183yENGzL6di289E8QTzyxi"

	payload := strings.Join([]string{
		`{"type":"user","uuid":"u1","parentUuid":null,"sessionId":"s1","message":{"content":[{"type":"text","text":"read the env"}]}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","message":{"id":"m1","content":[{"type":"tool_use","id":"` + toolUseID + `","name":"Bash","input":{"command":"printenv"}}]}}`,
		`{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"` + toolUseID + `","content":"ok"}]},"toolUseResult":{"tool_use_id":"` + toolUseID + `","stdout":"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}}`,
	}, "\n") + "\n"

	res := scrubJSONL(t, s, "claude-code", payload)
	require.NotContainsf(t, string(res.Out), "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "secret survived:\n%s", res.Out)

	// Walk the redacted output the way a downstream parser would.
	byUUID := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(res.Out)), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		byUUID[rec["uuid"].(string)] = rec
	}
	require.Lenf(t, byUUID, 3, "expected 3 records, got %d", len(byUUID))
	assert.True(t, byUUID["a1"]["parentUuid"] == "u1" && byUUID["u2"]["parentUuid"] == "a1", "parent chain broken")
	content := byUUID["a1"]["message"].(map[string]any)["content"].([]any)
	assert.True(t, content[0].(map[string]any)["id"] == toolUseID, "tool_use block id broken — nothing can point at this call")
	toolResult := byUUID["u2"]["toolUseResult"].(map[string]any)
	assert.True(t, toolResult["tool_use_id"] == toolUseID, "tool_use_id broken — the subagent join would fail")
}

// Cursor stores a hex-encoded image inside the assembled request: a declared opaque
// payload, exempt via the NESTED PATH content[].image.hex rather than a field name.
func TestDeclaredOpaqueBinaryPayloadSurvivesTheEntropyBackstop(t *testing.T) {
	s := newScrubber(t)

	// Generated rather than repeated: repeating hex has LOW Shannon entropy and would
	// never reach the backstop, so the test would pass for the wrong reason.
	imageHex := pseudoRandomHex(t, 6000)
	line := `{"composerId":"c8cbeb0b","content":[{"type":"image","image":{"hex":"` + imageHex + `"}}]}`

	res := scrubJSONL(t, s, "cursor", line+"\n")
	assert.Contains(t, string(res.Out), imageHex, "the declared opaque payload was redacted; the entropy exemption did not apply")

	// The same bytes in a field that is NOT declared opaque are fair game.
	other := `{"composerId":"c8cbeb0b","content":[{"type":"text","text":"` + imageHex + `"}]}`
	res2 := scrubJSONL(t, s, "cursor", other+"\n")
	assert.NotContains(t, string(res2.Out), imageHex, "a high-entropy blob in an undeclared field should hit the backstop")
}

// pseudoRandomHex builds deterministic high-entropy hex from a fixed seed.
func pseudoRandomHex(t *testing.T, n int) string {
	t.Helper()
	const digits = "0123456789abcdef"
	out := make([]byte, n)
	state := uint64(0x2545F4914F6CDD1D)
	for i := range out {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out[i] = digits[state%16]
	}
	return string(out)
}

// path_user is a rewriter, not a detector, so it runs on exempt fields too.
func TestPathUserRewritesEverywhereIncludingExemptFields(t *testing.T) {
	s := newScrubber(t)

	line := `{"type":"user","uuid":"u1","cwd":"/Users/jane/work/api",` +
		`"timestamp":"/Users/jane/x","message":{"content":[{"type":"text","text":"see /Users/jane/work/api/db.go"}]}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	out := string(res.Out)

	assert.NotContainsf(t, out, "/Users/jane", "username survived in a path:\n%s", out)
	assert.Containsf(t, out, "/Users/__USER__/work/api", "path shape was not preserved — paths must stay comparable across sessions:\n%s", out)
	assert.NotEqual(t, 0, res.RuleHits["path-user"])
}

// A torn tail is raw-scanned and ships: a truncated last line is a parse-miss, never
// an engine error.
func TestTornTailIsRawScannedAndShips(t *testing.T) {
	s := newScrubber(t)

	payload := `{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"fine"}]}}` + "\n" +
		`{"type":"assistant","uuid":"a1","message":{"content":[{"type":"text","text":"ghp_abcdefghijklmnopqrstuvwxyz0123456789 and tru`

	res, err := s.Scrub([]byte(payload), transforms.Hint{Family: "claude-code", JSONL: true})
	require.NoErrorf(t, err, "a torn tail must not be an engine error: %v", err)
	out := string(res.Out)

	assert.NotContains(t, out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "the pattern packs must still scan a torn line")
	assert.Truef(t, res.LinesParsed == 1 && res.LinesRawScanned == 1, "expected 1 parsed and 1 raw-scanned line, got %d and %d", res.LinesParsed, res.LinesRawScanned)
	assert.Equalf(t, transforms.ScanModeMixed, res.ScanMode, "scan_mode should be mixed, got %q", res.ScanMode)
	assert.True(t, !strings.HasSuffix(out, "\n"), "a missing final newline must not be added back: that would be fixing a tail")
}

// A non-JSON payload is raw-scanned rather than skipped.
func TestNonJSONPayloadIsRawScanned(t *testing.T) {
	s := newScrubber(t)
	text := "$ printenv\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\nHOME=/Users/jane\n"

	res, err := s.Scrub([]byte(text), transforms.Hint{Family: "claude-code", JSONL: false})
	require.NoError(t, err)
	out := string(res.Out)
	assert.NotContainsf(t, out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "secret survived a raw-text scan:\n%s", out)
	assert.NotContainsf(t, out, "/Users/jane", "path_user must apply to raw text too:\n%s", out)
	assert.Equalf(t, transforms.ScanModeRawText, res.ScanMode, "scan_mode: %q", res.ScanMode)
}

// A base64-encoded secret is invisible to every regex, so one level is decoded and
// scanned. One level only: recursion is unbounded work per byte.
func TestOneLevelOfBase64IsDecodedAndScanned(t *testing.T) {
	s := newScrubber(t)

	inner := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	once := base64.StdEncoding.EncodeToString([]byte(inner))
	twice := base64.StdEncoding.EncodeToString([]byte(once))

	res := scrubJSONL(t, s, "claude-code",
		`{"type":"user","message":{"content":[{"type":"text","text":"`+once+`"}]}}`+"\n")
	assert.NotContainsf(t, string(res.Out), once, "a base64-wrapped secret must be caught:\n%s", res.Out)

	// Double encoding is out of scope by design; pinning it documents the boundary.
	res2 := scrubJSONL(t, s, "claude-code",
		`{"type":"user","message":{"content":[{"type":"text","text":"`+twice+`"}]}}`+"\n")
	_ = res2 // no assertion on catching it; the entropy backstop may or may not fire
}

// A recorded over-redaction, left alone deliberately. In a postgres URL the url-userinfo
// and email rules overlap, and the wider span wins: it takes the hostname with the
// password and attributes the hit to email. The safe direction on an overlap is the wider
// span, since preferring the narrower risks leaving a tail of a secret in the clear.
func TestKnownOverRedactionInConnectionStrings(t *testing.T) {
	s := newScrubber(t)
	line := `{"type":"user","toolUseResult":{"stdout":"psql postgres://app:hunter2@db.internal:5432/prod"}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	out := string(res.Out)

	assert.NotContains(t, out, "hunter2", "the password must not survive")
	assert.NotContains(t, out, "db.internal", "the hostname now survives — the overlap rule changed; update this note")
}

func TestDensityAndRuleHitLedger(t *testing.T) {
	s := newScrubber(t)

	clean := `{"type":"user","message":{"content":[{"type":"text","text":"nothing to see"}]}}` + "\n"
	res := scrubJSONL(t, s, "claude-code", clean)
	assert.Equalf(t, float64(0), res.Density(), "a clean record should have zero density, got %v", res.Density())

	dirty := `{"type":"user","message":{"content":[{"type":"text","text":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}}` + "\n"
	res = scrubJSONL(t, s, "claude-code", dirty)
	assert.Truef(t, res.Density() > 0 && res.Density() <= 1, "density out of range: %v", res.Density())
	assert.Equal(t, 1, res.RuleHits["github-pat"])
	assert.Equalf(t, len(dirty), res.BytesTotal, "bytes_total %d, want %d", res.BytesTotal, len(dirty))
}

// A pack named in config but absent from the corpus must fail loudly: running with fewer
// rules than configured weakens the floor with no signal.
func TestUnknownPackIsAnError(t *testing.T) {
	cfg := transforms.DefaultConfig()
	cfg.RulePacks = append(cfg.RulePacks, "acme-invented")
	if _, err := transforms.New(cfg); err == nil {
		t.Fatal("an unknown rule pack must be refused at compile time")
	}
}

// buildRecordWithValueAt plants a value at a dotted path ("[]" meaning an array element),
// so the fixture can hit exactly the path an exemption names.
func buildRecordWithValueAt(t *testing.T, path, value string) string {
	t.Helper()

	var valueAt any = value
	for _, segment := range slices.Backward(strings.Split(path, ".")) {
		name, array := strings.CutSuffix(segment, "[]")
		if array {
			valueAt = []any{valueAt}
		}
		valueAt = map[string]any{name: valueAt}
	}
	rec := valueAt.(map[string]any)
	rec["type"] = "user"
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	return string(raw)
}

// The compiled default must protect the identifier spine on its own: exemptions once
// reached the scrubber through config resolution only, so DefaultConfig() redacted the ids
// joining a subagent transcript to its parent. Both ends redact to the same sentinel, which
// is what makes it silent.
func TestTheCompiledDefaultProtectsTheIdentifierSpine(t *testing.T) {
	s, err := transforms.New(transforms.DefaultConfig())
	require.NoError(t, err)

	// High-entropy on purpose: this is the shape the backstop fires on.
	const id = "toolu_01FcSqsnNxWeeDGKyfZKjJHbXk9QwErTyU"
	for _, field := range []string{"toolUseId", "sessionId", "uuid", "requestId"} {
		in := `{"` + field + `":"` + id + `"}` + "\n"
		res, err := s.Scrub([]byte(in), transforms.Hint{Family: "claude-code", JSONL: true})
		require.NoError(t, err)
		assert.Equalf(t, in, string(res.Out), "%s was redacted by the compiled default:\n got %s\nwant %s", field, res.Out, in)
	}

	// Exemption is detector-scoped: a credential planted in an exempt field is still caught.
	res, err := s.Scrub([]byte(`{"toolUseId":"AKIAIOSFODNN7EXAMPLE"}`+"\n"),
		transforms.Hint{Family: "claude-code", JSONL: true})
	require.NoError(t, err)
	assert.NotContainsf(t, string(res.Out), "AKIAIOSFODNN7EXAMPLE", "a credential in an exempt field survived: %s", res.Out)

	// And a field nobody exempted is still scanned, or the test above proves nothing.
	res, err = s.Scrub([]byte(`{"someField":"`+id+`"}`+"\n"),
		transforms.Hint{Family: "claude-code", JSONL: true})
	require.NoError(t, err)
	assert.Containsf(t, string(res.Out), "__REDACTED:", "an unexempted high-entropy value was not redacted: %s", res.Out)
}

// A pattern that backtracks pathologically stalls an install for seconds without erroring, so the
// worst case has to be kept. One Scrubber serves every worker, hence the atomic.
func TestTheScrubberKeepsItsWorstCase(t *testing.T) {
	s, err := transforms.New(transforms.DefaultConfig())
	require.NoError(t, err)
	if d, n := s.Slowest(); d != 0 || n != 0 {
		t.Fatalf("a fresh Scrubber claims a slowest scrub: %v over %d bytes", d, n)
	}

	small := []byte(`{"a":"x"}`)
	big := make([]byte, 0, 64<<10)
	for len(big) < 64<<10 {
		big = append(big, `{"msg":"the quick brown fox jumps over the lazy dog"}`+"\n"...)
	}
	if _, err := s.Scrub(big, transforms.Hint{JSONL: true}); err != nil {
		t.Fatal(err)
	}
	afterBig, bytesBig := s.Slowest()
	assert.NotEqual(t, time.Duration(0), afterBig, "scrubbing 64 KB registered no cost at all")
	assert.Equalf(t, int64(len(big)), bytesBig, "slowest scrub is attributed to %d bytes, want %d", bytesBig, len(big))

	// The small one must not displace it: this is a maximum, not a last-value.
	if _, err := s.Scrub(small, transforms.Hint{JSONL: true}); err != nil {
		t.Fatal(err)
	}
	if d, n := s.Slowest(); d != afterBig || n != bytesBig {
		t.Errorf("a cheaper scrub overwrote the worst case: %v over %d bytes", d, n)
	}
}
