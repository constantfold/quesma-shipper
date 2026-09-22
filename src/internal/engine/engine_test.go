package engine_test

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
)

// Every collection preserves graph identifiers, sealed integrity, classification and install ownership.
func TestCollectionContract(t *testing.T) {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	const secretLine = `{"type":"user","uuid":"u1","parentUuid":null,"sessionId":"s1","cwd":"/Users/jane/work",` +
		`"message":{"content":[{"type":"text","text":"key ` + secret + `"}]}}` + "\n"
	for _, tc := range []struct {
		name, organization, body string
		hits                     int
	}{
		{"plain", "", line1, 0},
		{"redacted", "", secretLine, 1},
		{"organization", "acme", line1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.plan.OrganizationID = tc.organization
			f.writeTranscript("p/s1.jsonl", tc.body)
			require.Equal(t, 1, f.run().Shipped)
			keys := f.port.keys()
			require.Len(t, keys, 1)
			root, err := formats.InstallRoot(cmp.Or(tc.organization, "default"), f.unit.InstallID.String())
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(keys[0], root+"/"), keys[0])

			obj, m, payload := f.openObject(t, keys[0])
			assert.Contains(t, m.NativePath, "s1.jsonl")
			assert.Contains(t, string(payload), `"uuid":"u1"`, "the graph must survive scrubbing")
			assert.Equal(t, "trajectory", m.ArtifactClass)
			assert.Equal(t, m.ArtifactClass, obj.Metadata["artifact-class"])
			assert.NotEmpty(t, obj.Metadata["shipped-hash"])
			assert.Equal(t, m.ShippedHash, obj.Metadata["shipped-hash"])
			assert.NotContains(t, string(payload), secret)
			require.NotNil(t, m.Redaction)
			assert.Equal(t, tc.hits, m.Redaction.RuleHits["github-pat"])
			if tc.hits > 0 {
				assert.Positive(t, m.Redaction.Density, "the rule-drift alarm must record density")
			}
		})
	}
}

// Both shipped and unchanged files advance progress through every decided file.
func TestProgressStreamsEveryDecidedFile(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line1)

	type event struct {
		done, total int
		decision    auditlog.Decision
	}
	for _, decision := range []auditlog.Decision{auditlog.DecisionShipped, auditlog.DecisionUnchanged} {
		var events []event
		f.run(func(o *engine.Options) {
			o.Progress = func(sourceID string, done, total int, fo engine.FileOutcome) {
				assert.Equal(t, "claude-code-transcripts", sourceID)
				events = append(events, event{done, total, fo.Decision})
			}
		})
		assert.Equal(t, []event{{1, 2, decision}, {2, 2, decision}}, events)
	}
}

func TestHealthIsReportedPerSource(t *testing.T) {
	f := newFixture(t)
	// Root exists, nothing matches.
	require.NoError(t, os.MkdirAll(filepath.Join(f.home, ".claude", "projects"), 0o700))

	rep := f.run()
	require.Lenf(t, rep.Sources, 1, "expected 1 source, got %d", len(rep.Sources))
	assert.Equalf(t, formats.RootPresentNoMatch, rep.Sources[0].Health, "health %q, want root_present_no_match", rep.Sources[0].Health)
	assert.NotEqual(t, "", rep.Sources[0].Reason, "a non-collected health state must carry a reason")
}
