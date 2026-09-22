package engine_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// The heartbeat carries per-source state and counts, never transcript bytes, object keys or paths.
func TestHeartbeat(t *testing.T) {
	now := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	rep := formats.Report{
		StartedAt: now,
		Sources: []formats.SourceOutcome{
			{
				SourceID: "claude-code-transcripts", Family: "claude-code",
				Health: formats.Collected, Sniff: formats.SniffOK, AgentVersion: "2.1.220",
				Files: []formats.FileOutcome{
					{Decision: auditlog.DecisionShipped, Density: 0.02,
						NativePath: "/Users/__USER__/.claude/projects/p/a.jsonl",
						ObjectKey:  "v1/organization=default/install=x/mirror/source=s/abc.age"},
					{Decision: auditlog.DecisionUnchanged},
				},
			},
			{SourceID: "cursor-transcripts", Family: "cursor", Health: formats.RootPresentNoMatch, Reason: "root exists but no file matched"},
			{SourceID: "codex-rollouts", Family: "codex", Health: formats.AgentAbsent, Reason: "not installed"},
		},
	}
	hb := (engine.Heartbeat{
		OrganizationID: "default", InstallID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		ClientVersion: "0.1.0", ConfigVersion: 1,
	}).WithReport(rep, now)
	body, err := hb.Encode()
	require.NoError(t, err)

	// Matched against field names: "cursor" alone also matches the source id "cursor-transcripts".
	for _, forbidden := range []string{
		"abc.age", `"object_key"`, `"cursor_before"`, `"cursor_after"`, `"offset"`,
		`"native_path"`, ".jsonl", "/Users/", "projects/",
	} {
		assert.NotContainsf(t, string(body), forbidden, "heartbeat contains %q — it must not be upload tracking:\n%s", forbidden, body)
	}
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	for _, want := range []string{"install_id", "client_version", "config_version", "sources"} {
		assert.Contains(t, parsed, want)
	}

	byID := map[string]engine.SourceHealth{}
	for _, s := range hb.Sources {
		byID[s.SourceID] = s
	}
	// Expected silence and drift look alike from a distance and must stay distinct.
	assert.Equal(t, string(formats.AgentAbsent), byID["codex-rollouts"].State)
	assert.Equal(t, string(formats.RootPresentNoMatch), byID["cursor-transcripts"].State)
	cc := byID["claude-code-transcripts"]
	assert.Truef(t, cc.Shipped == 1 && cc.Unchanged == 1, "counts: shipped %d unchanged %d", cc.Shipped, cc.Unchanged)
	assert.Positive(t, cc.RedactionDensity, "redaction density is the rule-drift alarm")
	assert.Equal(t, "2.1.220", cc.AgentVersion)
}
