package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources/sqliteread"
)

type accounts struct {
	client   *http.Client
	keychain func(context.Context, string) ([]byte, error)
}

type accountObservation struct {
	Source     string          `json:"source"`
	ObservedAt time.Time       `json:"observed_at"`
	HTTPStatus int             `json:"http_status,omitempty"`
	Error      string          `json:"error,omitempty"`
	Body       json.RawMessage `json:"body,omitempty"`
}

func (p *accounts) discover(req Request) (Discovery, error) {
	d := Discovery{Health: formats.RootPresentNoMatch, Sniff: formats.SniffOK}
	if req.Source.Root == "" {
		d.Health = formats.AgentAbsent
		return d, nil
	}
	if !req.Capture {
		d.Deferred = true
		d.Reason = "configured; checked during collection"
		return d, nil
	}
	if req.Now == nil || req.Context == nil || req.Env.Home == "" {
		return d, fmt.Errorf("account collection requires clock, context and home")
	}
	if req.Interval <= 0 {
		return d, fmt.Errorf("account collection requires a positive interval")
	}
	bucket := req.Now().UTC().Truncate(req.Interval)
	name := strings.TrimSuffix(req.Source.ID, "-account") + ".account." + bucket.Format("20060102T150405Z") + ".jsonl"
	// The size bound stays stable within a bucket and reserves memory before loading.
	d.Candidates = []Candidate{{Path: name, RelPath: name, Size: req.Source.MaxFileBytes, MTime: bucket,
		Load: func(ctx context.Context) (Payload, error) { return p.load(ctx, req, bucket) },
	}}
	d.Health = formats.Collected
	return d, nil
}

func (p *accounts) load(ctx context.Context, req Request, bucket time.Time) (Payload, error) {
	if err := ctx.Err(); err != nil {
		return Payload{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	observations, present := p.collect(ctx, req)
	if !present {
		return Payload{}, os.ErrNotExist
	}
	if err := ctx.Err(); err != nil {
		return Payload{}, err
	}
	payload := Payload{MTime: bucket}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	for _, obs := range observations {
		if err := encoder.Encode(struct {
			BucketStart time.Time `json:"bucket_start"`
			accountObservation
		}{bucket, obs}); err != nil {
			return Payload{}, err
		}
		if obs.Error != "" {
			payload.Warning = "partial account snapshot: " + obs.Source + ": " + obs.Error
		}
	}
	if req.Source.MaxFileBytes > 0 && int64(raw.Len()) > req.Source.MaxFileBytes {
		return Payload{}, fmt.Errorf("%w: generated content exceeds file size limit", platform.ErrTooLarge)
	}
	payload.Bytes = raw.Bytes()
	return payload, nil
}

func (p *accounts) collect(ctx context.Context, req Request) ([]accountObservation, bool) {
	switch req.Source.ID {
	case "claude-account":
		return p.collectClaude(ctx, req)
	case "codex-account":
		return p.collectCodex(ctx, req)
	case "cursor-account":
		return p.collectCursor(ctx, req)
	default:
		return []accountObservation{localAccount(req, "account", nil, fmt.Errorf("unsupported account source"))}, true
	}
}

const accountResponseLimit = 1 << 20

type accountEndpoint struct {
	source, method, url, body string
	headers                   map[string]string
}

func (p *accounts) observe(ctx context.Context, req Request, token string, endpoint accountEndpoint) accountObservation {
	obs := accountObservation{Source: endpoint.source, ObservedAt: req.Now().UTC()}
	if token == "" {
		obs.Error = "credentials_unavailable"
		return obs
	}
	var body io.Reader
	if endpoint.body != "" {
		body = strings.NewReader(endpoint.body)
	}
	request, err := http.NewRequestWithContext(ctx, endpoint.method, endpoint.url, body)
	if err != nil {
		obs.Error = "request_failed"
		return obs
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "quesma-shipper")
	for name, value := range endpoint.headers {
		if value != "" {
			request.Header.Set(name, value)
		}
	}
	return p.fetch(obs, request)
}

func localAccount(req Request, source string, body json.RawMessage, err error) accountObservation {
	obs := accountObservation{Source: source, ObservedAt: req.Now().UTC(), Body: body}
	if len(body) > accountResponseLimit {
		obs.Error = "response_too_large"
		obs.Body = nil
	}
	if err != nil {
		obs.Error = "store_unreadable"
		obs.Body = nil
	}
	return obs
}

func accountPathExists(path string) bool { _, err := os.Stat(path); return !os.IsNotExist(err) }

func accountJSON(path string, limit int64) (map[string]json.RawMessage, error) {
	raw, _, err := platform.ReadWhole(path, limit)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	err = json.Unmarshal(raw, &doc)
	return doc, err
}

func (p *accounts) fetch(obs accountObservation, request *http.Request) accountObservation {
	client := http.Client{Timeout: 10 * time.Second}
	if p.client != nil {
		client = *p.client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		obs.Error = "request_failed"
		return obs
	}
	defer response.Body.Close()
	obs.HTTPStatus = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		obs.Error = "http_error"
		return obs
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, accountResponseLimit+1))
	if err != nil {
		obs.Error = "response_unreadable"
		return obs
	}
	if len(raw) > accountResponseLimit {
		obs.Error = "response_too_large"
		return obs
	}
	if !json.Valid(raw) {
		obs.Error = "invalid_json"
		return obs
	}
	obs.Body = raw
	return obs
}

func (p *accounts) collectClaude(ctx context.Context, req Request) ([]accountObservation, bool) {
	var out []accountObservation
	env := req.Env
	if env.Lookup == nil {
		env.Lookup = func(string) (string, bool) { return "", false }
	}
	home := req.Source.Root
	config := filepath.Join(env.Home, ".claude.json")
	service := "Claude Code-credentials"
	override, _ := env.Lookup("CLAUDE_CONFIG_DIR")
	if home != filepath.Join(env.Home, ".claude") || override != "" && filepath.Clean(override) == home {
		config = filepath.Join(home, ".claude.json")
		keychainHome := home
		if override != "" && filepath.Clean(override) == home {
			keychainHome = override
		}
		sum := sha256.Sum256([]byte(keychainHome))
		service = fmt.Sprintf("Claude Code-credentials-%x", sum[:4])
	}
	doc, err := accountJSON(config, 64<<20)
	if err != nil || len(doc["oauthAccount"]) > 0 {
		out = append(out, localAccount(req, "claude.local.oauthAccount", doc["oauthAccount"], err))
	}
	var raw []byte
	if runtime.GOOS == "darwin" && err == nil && bytes.HasPrefix(bytes.TrimSpace(doc["oauthAccount"]), []byte("{")) {
		read := p.keychain
		if read == nil {
			read = readAccountKeychain
		}
		raw, _ = read(ctx, service)
	}
	if len(raw) == 0 {
		raw, _, _ = platform.ReadWhole(filepath.Join(home, ".credentials.json"), accountResponseLimit)
	}
	var creds struct {
		OAuth struct {
			Token  string   `json:"accessToken"`
			Scopes []string `json:"scopes"`
		} `json:"claudeAiOauth"`
	}
	credentialErr := json.Unmarshal(raw, &creds)
	token := creds.OAuth.Token
	if credentialErr != nil || !slices.Contains(creds.OAuth.Scopes, "user:profile") {
		token = ""
	}
	for _, endpoint := range []string{"profile", "usage"} {
		out = append(out, p.observe(ctx, req, token, accountEndpoint{
			source: "claude.oauth." + endpoint, method: "GET",
			url:     "https://api.anthropic.com/api/oauth/" + endpoint,
			headers: map[string]string{"anthropic-beta": "oauth-2025-04-20"},
		}))
	}
	return out, true
}

func (p *accounts) collectCodex(ctx context.Context, req Request) ([]accountObservation, bool) {
	var out []accountObservation
	home := req.Source.Root
	path := filepath.Join(home, "auth.json")
	if !accountPathExists(home) {
		return nil, false
	}
	doc, err := accountJSON(path, accountResponseLimit)
	var tokens struct {
		Access    string `json:"access_token"`
		ID        string `json:"id_token"`
		AccountID string `json:"account_id"`
	}
	if tokenErr := json.Unmarshal(doc["tokens"], &tokens); tokenErr != nil {
		tokens.Access = ""
	}
	metadata := map[string]json.RawMessage{}
	if mode := doc["auth_mode"]; len(mode) > 0 {
		metadata["auth_mode"] = mode
	}
	parts := strings.Split(tokens.ID, ".")
	if len(parts) == 3 {
		claims, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
		if decodeErr == nil && json.Valid(claims) {
			metadata["id_token_claims"] = claims
		}
	}
	body, _ := json.Marshal(metadata)
	out = append(out, localAccount(req, "codex.local.account", body, err))
	out = append(out, p.observe(ctx, req, tokens.Access, accountEndpoint{
		source: "codex.wham.usage", method: "GET", url: "https://chatgpt.com/backend-api/wham/usage",
		headers: map[string]string{"ChatGPT-Account-Id": tokens.AccountID},
	}))
	return out, true
}

func (p *accounts) collectCursor(ctx context.Context, req Request) ([]accountObservation, bool) {
	var out []accountObservation
	path := filepath.Join(req.Source.Root, "state.vscdb")
	if !accountPathExists(path) {
		return nil, false
	}
	values, token, err := sqliteread.CursorAccount(ctx, path)
	body, _ := json.Marshal(values)
	out = append(out, localAccount(req, "cursor.local.account", body, err))
	for _, endpoint := range []string{"GetPlanInfo", "GetCurrentPeriodUsage"} {
		out = append(out, p.observe(ctx, req, token, accountEndpoint{
			source: "cursor.dashboard." + endpoint, method: "POST", body: "{}",
			url:     "https://api2.cursor.sh/aiserver.v1.DashboardService/" + endpoint,
			headers: map[string]string{"Content-Type": "application/json", "Connect-Protocol-Version": "1"},
		}))
	}
	return out, true
}
