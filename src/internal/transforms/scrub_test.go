package transforms

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newScrubber(t *testing.T) *Scrubber {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Username = "jane"
	s, err := New(cfg)
	require.NoError(t, err)
	return s
}

func scrubJSONL(t *testing.T, s *Scrubber, family, payload string) Result {
	t.Helper()
	res, err := s.Scrub([]byte(payload), Hint{Family: family, JSONL: true})
	require.NoError(t, err, "scrub returned an engine error")
	return res
}

// Each secret travels in tool output, as it reaches a transcript; rule claims a hit unless overlaps make it ambiguous.
func TestLeaksAreRedacted(t *testing.T) {
	s := newScrubber(t)
	type leak struct {
		name, text string
		leaks      []string
		rule, kept string // kept is the part that is signal, not the secret
	}
	key := func(name, secret, rule string) leak {
		return leak{name, "the key is " + secret + " ok", []string{secret}, rule, ""}
	}
	// printenv and kubectl output: only the name gives the value away, and only the value goes.
	env := func(name, sep, value string) leak {
		return leak{"env " + name, name + sep + value, []string{value}, "", name}
	}
	const awsKeyID = "AKIAIOSFODNN7EXAMPLE"
	const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	cases := []leak{
		key("github pat", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github-pat"),
		key("github fine-grained pat", "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP", "github-fine-grained-pat"),
		key("aws access key id", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"),
		key("openai key", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "openai-api-key"),
		key("anthropic key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", "anthropic-api-key"),
		key("slack bot token", "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", "slack-token"),
		key("stripe live key", "sk_live_abcdefghijklmnopqrstuvwx", "stripe-secret-key"),
		key("google api key", "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456", "google-api-key"),
		key("npm token", "npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm-token"),
		key("gitlab pat", "glpat-abcdefghijklmnopqrst", "gitlab-pat"),
		key("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", "jwt"),
		key("digitalocean pat", "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "digitalocean-token"),
		key("huggingface token", "hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh", "huggingface-access-token"),
		key("vault service token", "hvs.CAESIJ0123456789abcdefghijklmnopqrstuvwxyz", "vault-token"),
		key("age secret key", "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE", "age-secret-key"),
		key("groq key", "gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "groq-api-key"),
		key("xai key", "xai-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqr", "xai-api-key"),
		key("perplexity key", "pplx-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV", "perplexity-api-key"),
		key("dockerhub pat", "dckr_pat_abcdefghijklmnopqrstuvwxyzA", "dockerhub-token"),
		key("tailscale key", "tskey-auth-kFGiAS7CNTRL-abcdefghijklmnopqrstuv", "tailscale-key"),
		key("gitlab runner token", "glrt-abcdefghijklmnopqrst0", "gitlab-token-family"),
		key("stripe webhook secret", "whsec_abcdefghijklmnopqrstuvwxyzABCDEF", "stripe-webhook-secret"),
		key("atlassian api token", "ATATT3"+strings.Repeat("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 3), "atlassian-api-token"),
		key("azure ad client secret", "abc8Q~dEfGhIjKlMnOpQrStUvWxYz0123456789~", "azure-ad-client-secret"),
		// The aws CLI labels it "SecretAccessKey" inside JSON-in-string, where key-name cannot see it.
		{"aws cli create-access-key output", `{\"AccessKey\": {\"UserName\": \"ingest\", \"AccessKeyId\": \"` + awsKeyID + `\", \"SecretAccessKey\": \"` + awsSecret + `\", \"Status\": \"Active\"}}`, []string{awsSecret, "wJalrXUtnFEMI", awsKeyID}, "secret-access-key", ""},
		{"aws yaml-style label", "SecretAccessKey: " + awsSecret, []string{awsSecret, "wJalrXUtnFEMI"}, "secret-access-key", ""},
		{"aws env-style label", "aws_secret_access_key = " + awsSecret, []string{awsSecret, "wJalrXUtnFEMI"}, "aws-secret-key", ""},
		// Slash-carrying secrets rely on the pattern packs, since "/" is outside the entropy alphabet.
		{"azure storage account key", "DefaultEndpointsProtocol=https;AccountKey=abc123/def456+ghi789/jkl012+mno345/pqr678stu901vwx234yz567EXAMPLE==;", []string{"abc123/def456+ghi789/jkl012+mno345/pqr678stu901vwx234yz567EXAMPLE=="}, "", ""},
		{"bearer token with slashes", "curl -H 'Authorization: Bearer x7Jq/2mVp+Rw9sTk/EXAMPLE='", []string{"x7Jq/2mVp+Rw9sTk/EXAMPLE="}, "", ""},
		// A PEM block spans lines inside one JSON string, the shape a regex over raw bytes mangles.
		{"private key block", "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA3x2n\\n-----END RSA PRIVATE KEY-----", []string{"MIIEowIBAAKCAQEA3x2n"}, "private-key-block", ""},
		// A deliberate over-redaction: url-userinfo and email overlap, and the wider span takes the host.
		{"postgres url", "psql postgres://app:hunter2@db.internal:5432/prod", []string{"hunter2", "db.internal"}, "", ""},
		env("AWS_SECRET_ACCESS_KEY", "=", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
		env("DATABASE_URL", "=", "postgres://app:hunter2@db.internal:5432/prod"),
		env("MY_SERVICE_TOKEN", "=", "plain-looking-value-1234"),
		env("ACME_PASSWORD", ": ", "correct-horse-battery"),
		env("internal_secret", " = ", "abcdefghijklmno"),
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scrubJSONL(t, s, "claude-code", `{"type":"user","toolUseResult":{"stdout":"`+c.text+`"}}`+"\n")
			for _, leak := range c.leaks {
				assert.NotContains(t, string(res.Out), leak)
			}
			assert.Contains(t, string(res.Out), "__REDACTED:")
			if c.rule != "" {
				assert.NotZero(t, res.RuleHits[c.rule], "ledger %v", res.RuleHits)
			}
			assert.Contains(t, string(res.Out), c.kept)
		})
	}
}

// A planted secret in EVERY exempt field is still caught: exemptions scope only the heuristics.
func TestPlantedSecretInEveryExemptFieldIsStillCaught(t *testing.T) {
	s := newScrubber(t)
	const planted = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

	for family, paths := range CompiledExemptions() {
		for _, path := range paths {
			t.Run(family+"/"+path, func(t *testing.T) {
				fam := strings.ReplaceAll(family, "*", "claude-code") // "*" applies to every family
				res := scrubJSONL(t, s, fam, buildRecordWithValueAt(t, path, planted)+"\n")
				assert.NotContainsf(t, string(res.Out), planted, "a planted secret survived in exempt field %q", path)
			})
		}
	}
}

// A redacted multi-record trajectory still reassembles: the join keys make a DAG of the lines.
func TestGraphReassemblesAfterScrub(t *testing.T) {
	// Production-length: below the backstop's 24-char floor this passed with NO exemptions.
	const toolUseID = "toolu_0183yENGzL6di289E8QTzyxi"

	payload := strings.Join([]string{
		`{"type":"user","uuid":"u1","parentUuid":null,"sessionId":"s1","message":{"content":[{"type":"text","text":"read the env"}]}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","message":{"id":"m1","content":[{"type":"tool_use","id":"` + toolUseID + `","name":"Bash","input":{"command":"printenv"}}]}}`,
		`{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"` + toolUseID + `","content":"ok"}]},"toolUseResult":{"tool_use_id":"` + toolUseID + `","stdout":"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}}`,
	}, "\n") + "\n"

	out := string(scrubJSONL(t, newScrubber(t), "claude-code", payload).Out)
	require.NotContains(t, out, "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY")
	for _, join := range []string{`"parentUuid":"u1"`, `"parentUuid":"a1"`, `"id":"` + toolUseID + `"`, `"tool_use_id":"` + toolUseID + `"`} {
		assert.Contains(t, out, join)
	}
	assert.Equal(t, 3, strings.Count(out, toolUseID), "a tool_use id was redacted: the subagent join would fail")
}

// path_user runs on exempt fields too; the 4.35 bits/char slug survives because candidates with the username skip.
func TestPathUserRewritesEverywhereIncludingExemptFields(t *testing.T) {
	s := newScrubber(t)
	line := `{"type":"user","uuid":"u1","cwd":"/Users/jane/work/api","timestamp":"/Users/jane/x","message":{"content":[` +
		`{"type":"text","text":"see /Users/jane/work/api/db.go and ~/.claude/projects/-Users-jane-Work2026-SampleOrg-blink-UI-webFrontend/f00.jsonl"}]}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	out := string(res.Out)
	assert.NotContains(t, out, "jane", "username survived in a path")
	// Paths must stay comparable across sessions.
	assert.Contains(t, out, "/Users/__USER__/work/api")
	assert.Contains(t, out, "-Users-__USER__-Work2026-SampleOrg-blink-UI-webFrontend")
	assert.NotZero(t, res.RuleHits["path-user"])
	assert.Zero(t, res.RuleHits["generic-entropy"])
}

// Payload shapes the ladder must see through: a torn tail and raw text still meet the packs, one level
// of base64 is decoded, and an exemption applies by NESTED PATH. The final newline is never altered.
func TestPayloadShapes(t *testing.T) {
	const pat = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	once := base64.StdEncoding.EncodeToString([]byte(pat))
	// Random, not repeated: repeating hex has LOW entropy and would never reach the backstop.
	imageHex := randomHex(&xorshift{state: 0x2545F4914F6CDD1D}, 6000)
	for _, tc := range []struct {
		name, family, payload string
		raw                   bool
		absent, present       []string
		mode                  string
	}{
		{name: "a torn tail is raw-scanned and ships, never an engine error", mode: ScanModeMixed, absent: []string{pat},
			payload: `{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"fine"}]}}` + "\n" +
				`{"type":"assistant","uuid":"a1","message":{"content":[{"type":"text","text":"` + pat + ` and tru`},
		{name: "a non-JSON payload is raw-scanned, path_user included", raw: true, mode: ScanModeRawText,
			payload: "$ printenv\nGITHUB_TOKEN=" + pat + "\nHOME=/Users/jane\n", absent: []string{pat, "/Users/jane"}},
		{name: "a base64-wrapped secret is decoded and scanned", absent: []string{once},
			payload: `{"type":"user","message":{"content":[{"type":"text","text":"` + once + `"}]}}` + "\n"},
		{name: "cursor's declared opaque image survives the backstop", family: "cursor", present: []string{imageHex},
			payload: `{"composerId":"c8cbeb0b","content":[{"type":"image","image":{"hex":"` + imageHex + `"}}]}` + "\n"},
		{name: "the same bytes in an undeclared field are fair game", family: "cursor", absent: []string{imageHex},
			payload: `{"composerId":"c8cbeb0b","content":[{"type":"text","text":"` + imageHex + `"}]}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := newScrubber(t).Scrub([]byte(tc.payload), Hint{Family: cmp.Or(tc.family, "claude-code"), JSONL: !tc.raw})
			require.NoError(t, err)
			for _, s := range tc.absent {
				assert.NotContains(t, string(res.Out), s)
			}
			for _, s := range tc.present {
				assert.Contains(t, string(res.Out), s)
			}
			if tc.mode != "" {
				assert.Equal(t, tc.mode, res.ScanMode)
			}
			assert.Equal(t, strings.HasSuffix(tc.payload, "\n"), strings.HasSuffix(string(res.Out), "\n"), "the final newline changed")
		})
	}
}

func TestDensityAndRuleHitLedger(t *testing.T) {
	s := newScrubber(t)

	clean := `{"type":"user","message":{"content":[{"type":"text","text":"nothing to see"}]}}` + "\n"
	assert.Zero(t, scrubJSONL(t, s, "claude-code", clean).Density())

	dirty := `{"type":"user","message":{"content":[{"type":"text","text":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}}` + "\n"
	res := scrubJSONL(t, s, "claude-code", dirty)
	assert.True(t, res.Density() > 0 && res.Density() <= 1, "density out of range: %v", res.Density())
	assert.Equal(t, 1, res.RuleHits["github-pat"])
	assert.Equal(t, len(dirty), res.BytesTotal)
}

// buildRecordWithValueAt plants a value at exactly the path an exemption names.
func buildRecordWithValueAt(t *testing.T, path, value string) string {
	t.Helper()

	var valueAt any = value
	for _, segment := range slices.Backward(strings.Split(path, ".")) {
		if name, array := strings.CutSuffix(segment, "[]"); array {
			valueAt = map[string]any{name: []any{valueAt}}
		} else {
			valueAt = map[string]any{name: valueAt}
		}
	}
	rec := valueAt.(map[string]any)
	rec["type"] = "user"
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	return string(raw)
}

// The compiled default protects the identifier spine on its own, not only through config resolution.
func TestTheCompiledDefaultProtectsTheIdentifierSpine(t *testing.T) {
	s, err := New(DefaultConfig())
	require.NoError(t, err)

	// High-entropy on purpose: this is the shape the backstop fires on.
	const id = "toolu_01FcSqsnNxWeeDGKyfZKjJHbXk9QwErTyU"
	for _, field := range []string{"toolUseId", "sessionId", "uuid", "requestId"} {
		in := `{"` + field + `":"` + id + `"}` + "\n"
		assert.Equal(t, in, string(scrubJSONL(t, s, "claude-code", in).Out), "%s was redacted by the compiled default", field)
	}

	// A field nobody exempted is still scanned, or the loop above proves nothing.
	assert.Contains(t, string(scrubJSONL(t, s, "claude-code", `{"someField":"`+id+`"}`+"\n").Out), "__REDACTED:")
}

// A pattern that backtracks pathologically stalls an install without erroring, so the worst case is kept.
func TestTheScrubberKeepsItsWorstCase(t *testing.T) {
	s, err := New(DefaultConfig())
	require.NoError(t, err)
	d, n := s.Slowest()
	require.True(t, d == 0 && n == 0, "a fresh Scrubber claims a slowest scrub: %v over %d bytes", d, n)

	small := []byte(`{"a":"x"}`)
	big := make([]byte, 0, 64<<10)
	for len(big) < 64<<10 {
		big = append(big, `{"msg":"the quick brown fox jumps over the lazy dog"}`+"\n"...)
	}
	_, err = s.Scrub(big, Hint{JSONL: true})
	require.NoError(t, err)
	afterBig, bytesBig := s.Slowest()
	assert.NotZero(t, afterBig, "scrubbing 64 KB registered no cost at all")
	assert.Equal(t, int64(len(big)), bytesBig)

	// The small one must not displace it: this is a maximum, not a last-value.
	_, err = s.Scrub(small, Hint{JSONL: true})
	require.NoError(t, err)
	d, n = s.Slowest()
	assert.True(t, d == afterBig && n == bytesBig, "a cheaper scrub overwrote the worst case: %v over %d bytes", d, n)
}

// An operator's own names must redact; a multi-byte one loses the prefilter, never the redaction.
func TestConfiguredKeyNamesRedact(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKeyNames = append(cfg.SecretKeyNames, "ACME_DEPLOY_SIG", "CLÉ_SECRÈTE")
	s, err := New(cfg)
	require.NoError(t, err)
	// The last: dropping the prefilter is the fallback; dropping a rule is not.
	for _, in := range []string{`{"ACME_DEPLOY_SIG":"hunter2"}`, `{"type":"user","text":"CLÉ_SECRÈTE=hunter2"}`, `{"type":"user","text":"GITHUB_TOKEN=hunter2"}`} {
		out := string(scrubJSONL(t, s, "claude-code", in+"\n").Out)
		assert.Contains(t, out, Sentinel("key-name"))
		assert.NotContains(t, out, "hunter2")
	}
}

// Config that would weaken scrubbing fails the build: an unknown pack would run fewer rules, and the
// candidate scanner would read a negative entropy floor as "every run fires".
func TestWeakeningConfigFailsTheBuild(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RulePacks = append(cfg.RulePacks, "acme-invented")
	_, err := New(cfg)
	require.Error(t, err, "an unknown rule pack must be refused at compile time")

	cfg = DefaultConfig()
	cfg.Entropy.MinLength = -3
	_, err = New(cfg)
	require.ErrorContains(t, err, "-3", "a negative min_length must not compile, and the error names it")

	// Zero stays legal: it clamps to a one-byte floor, which no positive threshold can tell apart.
	cfg.Entropy.MinLength = 0
	_, err = New(cfg)
	assert.NoError(t, err, "min_length 0 must still compile")
}

// The accepted residual: a bare std-base64 secret splits at "/" under MinLength (labeled: TestLeaksAreRedacted).
func TestBareBase64WithSlashIsAKnownEscape(t *testing.T) {
	const bare = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	line := `{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"deploy with ` + bare + ` for now"}]}}`
	res := scrubJSONL(t, newScrubber(t), "claude-code", line+"\n")
	assert.Contains(t, string(res.Out), bare, "the backstop now catches bare slash-bearing base64 — the trade-off moved; update this note")
}
