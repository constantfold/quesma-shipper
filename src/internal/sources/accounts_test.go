package sources

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

type accountTransport func(*http.Request) (*http.Response, error)

func (f accountTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func accountFixture(t *testing.T) Request {
	t.Helper()
	home := t.TempDir()
	return Request{
		Source:   Resolved{Source: Source{ID: "codex-account", Family: "codex", Gather: "account"}, Root: filepath.Join(home, ".codex")},
		StateDir: filepath.Join(home, "shipper"), Env: Env{Home: home, Lookup: func(string) (string, bool) { return "", false }},
		Context: context.Background(), Capture: true, Interval: 15 * time.Minute,
		Now: func() time.Time { return time.Date(2026, 9, 16, 14, 17, 3, 0, time.UTC) },
	}
}

func TestAccountSnapshotsPreserveProviderJSONInMemory(t *testing.T) {
	req := accountFixture(t)
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"dev@example.org","https://api.openai.com/auth":{"chatgpt_plan_type":"pro"}}`))
	writeFile(t, filepath.Join(req.Env.Home, ".codex", "auth.json"), `{"tokens":{"access_token":"fixture-access","refresh_token":"fixture-refresh","account_id":"workspace-1","id_token":"x.`+claims+`.x"}}`)
	calls := 0
	p := accounts{client: &http.Client{Transport: accountTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		assert.True(t, r.Header.Get("Authorization") == "Bearer fixture-access" && r.Header.Get("ChatGPT-Account-Id") == "workspace-1", "wrong authentication")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{ "unknown":{"input_tokens":9007199254740993,"utilization":123.456,"optional":null,"accessToken":"fixture-secret"}, "windows":[] }`)), Header: http.Header{}}, nil
	})}}
	req.Capture = false
	inspected, err := p.discover(req)
	require.Truef(t, err == nil && len(inspected.Candidates) == 0 && inspected.Deferred, "inspection: %+v %v", inspected, err)
	req.Capture = true
	// Discovery neither fetches nor writes; only Load does.
	first, err := p.discover(req)
	require.NoError(t, err)
	require.Truef(t, len(first.Candidates) == 1 && calls == 0, "first: %+v calls %d", first, calls)
	c := first.Candidates[0]
	require.Equal(t, "codex.account.20260916T141500Z.jsonl", c.RelPath, c.RelPath)
	payload, err := c.Load(req.Context)
	require.NoError(t, err)
	require.Equalf(t, 1, calls, "load calls %d", calls)
	raw := payload.Bytes
	for _, field := range []string{`"input_tokens":9007199254740993`, `"utilization":123.456`, `"optional":null`, `"windows":[]`, `"chatgpt_plan_type":"pro"`} {
		require.Containsf(t, string(raw), field, "lost %s: %s", field, raw)
	}
	again, err := p.discover(req)
	require.Truef(t, err == nil && len(again.Candidates) == 1 && calls == 1 && again.Candidates[0].Path == c.Path, "same bucket: %+v %v calls %d", again, err, calls)
	req.Now = func() time.Time { return time.Date(2026, 9, 16, 14, 31, 0, 0, time.UTC) }
	next, err := p.discover(req)
	require.Truef(t, err == nil && len(next.Candidates) == 1 && calls == 1 && next.Candidates[0].Path != c.Path, "new bucket: %+v %v calls %d", next, err, calls)
	require.NoDirExists(t, req.StateDir, "account collection wrote local state")
}

func TestAccountHTTPFailuresAreBoundedAndDoNotLeak(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unauthorized", 401, `fixture-secret`, "http_error"},
		{"rate limited", 429, `fixture-secret`, "http_error"},
		{"malformed", 200, `{"accessToken":"fixture-secret"`, "invalid_json"},
		{"oversized", 200, strings.Repeat("x", accountResponseLimit+1), "response_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := accounts{client: &http.Client{Transport: accountTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: http.Header{}}, nil
			})}}
			obs := p.observe(context.Background(), accountFixture(t), "fixture-secret", accountEndpoint{source: "test", method: "GET", url: "https://example.org"})
			require.Truef(t, obs.Error == tc.want && len(obs.Body) == 0, "%+v", obs)
		})
	}
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer origin.Close()
	obs := (&accounts{}).observe(context.Background(), accountFixture(t), "fixture-secret", accountEndpoint{source: "test", method: "GET", url: origin.URL})
	require.Truef(t, !redirected && obs.HTTPStatus == 302, "followed credential redirect: %+v", obs)
}

func TestClaudeUsesActiveCredentialsAndPreservesLocalAccount(t *testing.T) {
	req := accountFixture(t)
	req.Source.ID = "claude-account"
	req.Source.Family = "claude-code"
	home := filepath.Join(req.Env.Home, "other-claude")
	req.Source.Root = home
	req.Env.Lookup = func(k string) (string, bool) { return home, k == "CLAUDE_CONFIG_DIR" }
	writeFile(t, filepath.Join(home, ".claude.json"), `{"oauthAccount":{"organizationType":"max","future":42},"unrelated":"not collected"}`)
	writeFile(t, filepath.Join(home, ".credentials.json"), `{"claudeAiOauth":{"accessToken":"correct","scopes":["user:profile"]}}`)
	calls := 0
	p := accounts{keychain: func(context.Context, string) ([]byte, error) { return nil, errors.New("locked") }, client: &http.Client{Transport: accountTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		assert.True(t, r.Header.Get("Authorization") == "Bearer correct" && r.Header.Get("anthropic-beta") != "", "wrong Claude credentials")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"five_hour":null,"limits":[{"kind":"future","percent":111}]}`)), Header: http.Header{}}, nil
	})}}
	d, err := p.discover(req)
	require.NoError(t, err)
	payload, err := d.Candidates[0].Load(req.Context)
	require.NoError(t, err)
	require.Equalf(t, 2, calls, "calls %d", calls)
	raw := payload.Bytes
	lines := bytes.Split(raw, []byte("\n"))
	require.Truef(t, len(lines) == 4 && len(lines[3]) == 0, "expected three newline-terminated records: %s", raw)
	for i, line := range lines[:3] {
		var record struct {
			BucketStart time.Time `json:"bucket_start"`
			accountObservation
		}
		require.NoError(t, json.Unmarshal(line, &record))
		require.Truef(t, record.BucketStart.Equal(req.Now().Truncate(req.Interval)) && record.Source != "" && !record.ObservedAt.IsZero() && len(record.Body) != 0, "incomplete record %d: %s", i, line)
	}
	require.Truef(t, !bytes.Contains(raw, []byte(`"observations"`)) && !bytes.Contains(raw, []byte("not collected")) && bytes.Contains(raw, []byte(`"future":42`)), "%s", raw)
}

func TestAccountBucketUsesCollectionInterval(t *testing.T) {
	for _, interval := range []time.Duration{5 * time.Minute, 30 * time.Minute, 0, -time.Minute} {
		t.Run(interval.String(), func(t *testing.T) {
			req := accountFixture(t)
			req.Interval = interval
			writeFile(t, filepath.Join(req.Source.Root, "auth.json"), `{}`)
			d, err := (&accounts{}).discover(req)
			if interval <= 0 {
				require.Error(t, err, "accepted nonpositive interval")
				return
			}
			require.NoError(t, err)
			bucket := req.Now().UTC().Truncate(interval)
			// The records' bucket_start comes from the same bucket, checked in TestClaudeUsesActiveCredentials.
			require.Equal(t, "codex.account."+bucket.Format("20060102T150405Z")+".jsonl", d.Candidates[0].RelPath)
		})
	}
}

func TestCandidateLoadLimitsAndCancellation(t *testing.T) {
	req := accountFixture(t)
	req.Source.MaxFileBytes = 1
	path := filepath.Join(req.Source.Root, "auth.json")
	writeFile(t, path, `{}`)
	d, err := (&accounts{}).discover(req)
	require.NoError(t, err)
	for _, load := range []func(context.Context) (Payload, error){fileLoader(path, 1), d.Candidates[0].Load} {
		_, err := load(context.Background())
		require.ErrorIs(t, err, platform.ErrTooLarge)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = load(ctx)
		require.ErrorIs(t, err, context.Canceled)
	}
}
