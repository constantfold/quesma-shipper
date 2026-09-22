package transforms

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

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
	require.NoErrorf(t, err, "scrub returned an engine error: %v", err)
	return res
}

// Each secret travels in tool output, the way it reaches a transcript, and none of its leaks
// may survive. rule is the rule that must claim a hit, empty where overlapping rules make it ambiguous.
func TestLeaksAreRedacted(t *testing.T) {
	s := newScrubber(t)
	type leak struct {
		name, text string
		leaks      []string
		rule       string
	}
	key := func(name, secret, rule string) leak {
		return leak{name, "the key is " + secret + " ok", []string{secret}, rule}
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
		// The aws CLI labels the secret "SecretAccessKey" with no "aws" near it, inside JSON-in-string
		// where key-name scrubbing cannot see the field. No fragment may survive around a "/".
		{"aws cli create-access-key output", `{\"AccessKey\": {\"UserName\": \"ingest\", \"AccessKeyId\": \"` + awsKeyID + `\", \"SecretAccessKey\": \"` + awsSecret + `\", \"Status\": \"Active\"}}`, []string{awsSecret, "wJalrXUtnFEMI", awsKeyID}, "secret-access-key"},
		{"aws yaml-style label", "SecretAccessKey: " + awsSecret, []string{awsSecret, "wJalrXUtnFEMI"}, "secret-access-key"},
		{"aws env-style label", "aws_secret_access_key = " + awsSecret, []string{awsSecret, "wJalrXUtnFEMI"}, "aws-secret-key"},
		// Slash-carrying secrets rely on the pattern packs, since "/" is outside the entropy alphabet.
		{"azure storage account key", "DefaultEndpointsProtocol=https;AccountKey=abc123/def456+ghi789/jkl012+mno345/pqr678stu901vwx234yz567EXAMPLE==;", []string{"abc123/def456+ghi789/jkl012+mno345/pqr678stu901vwx234yz567EXAMPLE=="}, ""},
		{"bearer token with slashes", "curl -H 'Authorization: Bearer x7Jq/2mVp+Rw9sTk/EXAMPLE='", []string{"x7Jq/2mVp+Rw9sTk/EXAMPLE="}, ""},
		// A PEM block spans lines inside one JSON string, the shape a regex over raw bytes mangles.
		{"private key block", "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA3x2n\\n-----END RSA PRIVATE KEY-----", []string{"MIIEowIBAAKCAQEA3x2n"}, "private-key-block"},
		// A recorded over-redaction, left alone deliberately: url-userinfo and email overlap and the
		// wider span wins, taking the hostname too. Preferring the narrower risks a secret's tail.
		{"postgres url", "psql postgres://app:hunter2@db.internal:5432/prod", []string{"hunter2", "db.internal"}, ""},
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
		})
	}
}

// printenv and kubectl output: the value has no recognisable shape but the key does, and only
// the value goes: the name is useful signal and not the secret.
func TestKeyNameRulesCatchShapelessValues(t *testing.T) {
	s := newScrubber(t)
	for _, env := range []string{
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"DATABASE_URL=postgres://app:hunter2@db.internal:5432/prod",
		"MY_SERVICE_TOKEN=plain-looking-value-1234",
		"ACME_PASSWORD: correct-horse-battery",
		"internal_secret = abcdefghijklmno",
	} {
		t.Run(env, func(t *testing.T) {
			res := scrubJSONL(t, s, "claude-code", `{"type":"user","toolUseResult":{"stdout":"`+env+`"}}`+"\n")
			i := strings.IndexAny(env, "=:")
			assert.Contains(t, string(res.Out), strings.TrimSpace(env[:i]))
			assert.NotContains(t, string(res.Out), strings.TrimSpace(env[i+1:]))
		})
	}
}

// A planted secret in EVERY structurally exempt field is still caught: exemptions are
// detector-scoped, and the pattern packs scan every field regardless.
func TestPlantedSecretInEveryExemptFieldIsStillCaught(t *testing.T) {
	s := newScrubber(t)
	const planted = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

	for family, paths := range CompiledExemptions() {
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

// A redacted multi-record trajectory still reassembles: the join keys make a DAG of the lines.
func TestGraphReassemblesAfterScrub(t *testing.T) {
	s := newScrubber(t)

	// Production-length: below the backstop's 24-char floor this passed with NO exemptions.
	const toolUseID = "toolu_0183yENGzL6di289E8QTzyxi"

	payload := strings.Join([]string{
		`{"type":"user","uuid":"u1","parentUuid":null,"sessionId":"s1","message":{"content":[{"type":"text","text":"read the env"}]}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","message":{"id":"m1","content":[{"type":"tool_use","id":"` + toolUseID + `","name":"Bash","input":{"command":"printenv"}}]}}`,
		`{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","message":{"content":[{"type":"tool_result","tool_use_id":"` + toolUseID + `","content":"ok"}]},"toolUseResult":{"tool_use_id":"` + toolUseID + `","stdout":"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}}`,
	}, "\n") + "\n"

	out := string(scrubJSONL(t, s, "claude-code", payload).Out)
	require.NotContainsf(t, out, "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "secret survived:\n%s", out)
	for _, join := range []string{`"parentUuid":"u1"`, `"parentUuid":"a1"`, `"id":"` + toolUseID + `"`, `"tool_use_id":"` + toolUseID + `"`} {
		assert.Contains(t, out, join)
	}
	assert.Equal(t, 3, strings.Count(out, toolUseID), "a tool_use id was redacted: the subagent join would fail")
}

// Cursor stores a hex-encoded image, a declared opaque payload exempt via the NESTED PATH.
func TestDeclaredOpaqueBinaryPayloadSurvivesTheEntropyBackstop(t *testing.T) {
	s := newScrubber(t)

	// Random, not repeated: repeating hex has LOW entropy and would never reach the backstop.
	imageHex := randomHex(&xorshift{state: 0x2545F4914F6CDD1D}, 6000)
	line := `{"composerId":"c8cbeb0b","content":[{"type":"image","image":{"hex":"` + imageHex + `"}}]}`

	res := scrubJSONL(t, s, "cursor", line+"\n")
	assert.Contains(t, string(res.Out), imageHex, "the declared opaque payload was redacted; the entropy exemption did not apply")

	// The same bytes in a field that is NOT declared opaque are fair game.
	other := `{"composerId":"c8cbeb0b","content":[{"type":"text","text":"` + imageHex + `"}]}`
	res2 := scrubJSONL(t, s, "cursor", other+"\n")
	assert.NotContains(t, string(res2.Out), imageHex, "a high-entropy blob in an undeclared field should hit the backstop")
}

// path_user is a rewriter, not a detector, so it runs on exempt fields too. The mixed-case slug
// is one long entropy candidate at 4.35 bits/char that heuristics see BEFORE path-user rewrites
// it; it survives only because the matcher skips candidates carrying the username.
func TestPathUserRewritesEverywhereIncludingExemptFields(t *testing.T) {
	s := newScrubber(t)
	line := `{"type":"user","uuid":"u1","cwd":"/Users/jane/work/api","timestamp":"/Users/jane/x","message":{"content":[` +
		`{"type":"text","text":"see /Users/jane/work/api/db.go and ~/.claude/projects/-Users-jane-Work2026-SampleOrg-blink-UI-webFrontend/f00.jsonl"}]}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	out := string(res.Out)
	assert.NotContainsf(t, out, "jane", "username survived in a path:\n%s", out)
	// Paths must stay comparable across sessions.
	assert.Contains(t, out, "/Users/__USER__/work/api")
	assert.Contains(t, out, "-Users-__USER__-Work2026-SampleOrg-blink-UI-webFrontend")
	assert.NotZero(t, res.RuleHits["path-user"])
	assert.Zero(t, res.RuleHits["generic-entropy"])
}

// A torn tail is raw-scanned and ships: a parse-miss, never an engine error.
func TestTornTailIsRawScannedAndShips(t *testing.T) {
	s := newScrubber(t)

	payload := `{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"fine"}]}}` + "\n" +
		`{"type":"assistant","uuid":"a1","message":{"content":[{"type":"text","text":"ghp_abcdefghijklmnopqrstuvwxyz0123456789 and tru`

	res := scrubJSONL(t, s, "claude-code", payload)
	out := string(res.Out)

	assert.NotContains(t, out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "the pattern packs must still scan a torn line")
	assert.Truef(t, res.LinesParsed == 1 && res.LinesRawScanned == 1, "expected 1 parsed and 1 raw-scanned line, got %d and %d", res.LinesParsed, res.LinesRawScanned)
	assert.Equalf(t, ScanModeMixed, res.ScanMode, "scan_mode should be mixed, got %q", res.ScanMode)
	assert.True(t, !strings.HasSuffix(out, "\n"), "a missing final newline must not be added back: that would be fixing a tail")
}

// A non-JSON payload is raw-scanned rather than skipped.
func TestNonJSONPayloadIsRawScanned(t *testing.T) {
	s := newScrubber(t)
	text := "$ printenv\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\nHOME=/Users/jane\n"

	res, err := s.Scrub([]byte(text), Hint{Family: "claude-code", JSONL: false})
	require.NoError(t, err)
	out := string(res.Out)
	assert.NotContainsf(t, out, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "secret survived a raw-text scan:\n%s", out)
	assert.NotContainsf(t, out, "/Users/jane", "path_user must apply to raw text too:\n%s", out)
	assert.Equalf(t, ScanModeRawText, res.ScanMode, "scan_mode: %q", res.ScanMode)
}

// A base64-encoded secret is invisible to every regex, so one level is decoded and scanned.
func TestOneLevelOfBase64IsDecodedAndScanned(t *testing.T) {
	s := newScrubber(t)

	once := base64.StdEncoding.EncodeToString([]byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789"))
	res := scrubJSONL(t, s, "claude-code", `{"type":"user","message":{"content":[{"type":"text","text":"`+once+`"}]}}`+"\n")
	assert.NotContainsf(t, string(res.Out), once, "a base64-wrapped secret must be caught:\n%s", res.Out)
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

// A pack named in config but absent from the corpus must fail loudly, not run with fewer rules.
func TestUnknownPackIsAnError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RulePacks = append(cfg.RulePacks, "acme-invented")
	_, newErr := New(cfg)
	require.Error(t, newErr, "an unknown rule pack must be refused at compile time")
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

// The compiled default must protect the identifier spine on its own: exemptions once arrived
// only through config resolution, so DefaultConfig() silently redacted the subagent join ids.
func TestTheCompiledDefaultProtectsTheIdentifierSpine(t *testing.T) {
	s, err := New(DefaultConfig())
	require.NoError(t, err)

	// High-entropy on purpose: this is the shape the backstop fires on.
	const id = "toolu_01FcSqsnNxWeeDGKyfZKjJHbXk9QwErTyU"
	for _, field := range []string{"toolUseId", "sessionId", "uuid", "requestId"} {
		in := `{"` + field + `":"` + id + `"}` + "\n"
		res := scrubJSONL(t, s, "claude-code", in)
		assert.Equalf(t, in, string(res.Out), "%s was redacted by the compiled default:\n got %s\nwant %s", field, res.Out, in)
	}

	// A field nobody exempted is still scanned, or the loop above proves nothing.
	res := scrubJSONL(t, s, "claude-code", `{"someField":"`+id+`"}`+"\n")
	assert.Containsf(t, string(res.Out), "__REDACTED:", "an unexempted high-entropy value was not redacted: %s", res.Out)
}

// A pattern that backtracks pathologically stalls an install without erroring, so the worst case is kept.
func TestTheScrubberKeepsItsWorstCase(t *testing.T) {
	s, err := New(DefaultConfig())
	require.NoError(t, err)
	if d, n := s.Slowest(); d != 0 || n != 0 {
		t.Fatalf("a fresh Scrubber claims a slowest scrub: %v over %d bytes", d, n)
	}

	small := []byte(`{"a":"x"}`)
	big := make([]byte, 0, 64<<10)
	for len(big) < 64<<10 {
		big = append(big, `{"msg":"the quick brown fox jumps over the lazy dog"}`+"\n"...)
	}
	_, scrubErr := s.Scrub(big, Hint{JSONL: true})
	require.NoError(t, scrubErr)
	afterBig, bytesBig := s.Slowest()
	assert.NotEqual(t, time.Duration(0), afterBig, "scrubbing 64 KB registered no cost at all")
	assert.Equalf(t, int64(len(big)), bytesBig, "slowest scrub is attributed to %d bytes, want %d", bytesBig, len(big))

	// The small one must not displace it: this is a maximum, not a last-value.
	_, smallScrubErr := s.Scrub(small, Hint{JSONL: true})
	require.NoError(t, smallScrubErr)
	if d, n := s.Slowest(); d != afterBig || n != bytesBig {
		t.Errorf("a cheaper scrub overwrote the worst case: %v over %d bytes", d, n)
	}
}

// A name carrying a multi-byte rune has no sound literal for the byte-folding automaton to filter
// on. The answer is to stop prefiltering the key-name regex, not to stop redacting.
func TestNonASCIIKeyNameStillRedacts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SecretKeyNames = append(cfg.SecretKeyNames, "CLÉ_SECRÈTE")
	s, err := New(cfg)
	require.NoErrorf(t, err, "a non-ASCII key name must compile, got %v", err)

	res := scrubJSONL(t, s, "claude-code", `{"type":"user","text":"CLÉ_SECRÈTE=hunter2"}`+"\n")
	assert.Containsf(t, string(res.Out), Sentinel("key-name"), "the secret survived: %s", res.Out)
	assert.NotContainsf(t, string(res.Out), "hunter2", "the secret survived verbatim: %s", res.Out)

	// Dropping the prefilter is the fallback; dropping a rule is not.
	res = scrubJSONL(t, s, "claude-code", `{"type":"user","text":"GITHUB_TOKEN=hunter2"}`+"\n")
	assert.NotContainsf(t, string(res.Out), "hunter2", "an ASCII name stopped firing next to a non-ASCII one: %s", res.Out)
}

// A negative floor is refused: `{-3,}` compiles as literal text ("never fires") while the
// candidate scanner reads it as "every run fires", and neither is what someone typing it means.
func TestNegativeEntropyMinLengthFailsTheBuild(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Entropy.MinLength = -3
	if _, err := New(cfg); err == nil {
		t.Fatal("a negative entropy min_length must not compile")
	} else if !strings.Contains(err.Error(), "-3") {
		t.Errorf("the error must name the offending value, got %v", err)
	}

	// Zero stays legal: it clamps to a one-byte floor, which no positive threshold can tell apart.
	cfg.Entropy.MinLength = 0
	_, newErr := New(cfg)
	assert.NoErrorf(t, newErr, "min_length 0 must still compile, got %v", newErr)
}

// The accepted residual of the path-entropy fix: a bare, UNLABELED std-base64 secret containing "/"
// splits at the slashes into segments under MinLength. Labeled arrivals of the same shape
// are still caught (TestLeaksAreRedacted), as are slash-free bare
// secrets over MinLength.
func TestBareBase64WithSlashIsAKnownEscape(t *testing.T) {
	s := newScrubber(t)

	const bare = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	line := `{"type":"user","uuid":"u1","message":{"content":[{"type":"text","text":"deploy with ` + bare + ` for now"}]}}`

	res := scrubJSONL(t, s, "claude-code", line+"\n")
	assert.Contains(t, string(res.Out), bare, "the backstop now catches bare slash-bearing base64 — the trade-off moved; update this note")
}
