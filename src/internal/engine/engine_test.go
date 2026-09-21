package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform/auditlog"
	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

func TestCollectsAndShips(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	rep := f.run()
	require.Equalf(t, 1, rep.Shipped, "expected 1 shipped, got %+v", rep)
	require.Lenf(t, f.port.keys(), 1, "expected 1 object, got %v", f.port.keys())

	// The object must be a real sealed container that opens with this install's identity.
	obj, _ := f.port.get(f.port.keys()[0])
	m, payload, err := transforms.Open(obj.Body, f.unit.Identity)
	require.NoErrorf(t, err, "the shipped object must open: %v", err)
	assert.Containsf(t, m.NativePath, "s1.jsonl", "manifest native_path: %q", m.NativePath)
	assert.Containsf(t, string(payload), `"uuid":"u1"`, "payload lost its identifiers: %s", payload)
	assert.Equalf(t, "trajectory", m.ArtifactClass, "artifact class %q", m.ArtifactClass)
	assert.Equalf(t, "trajectory", obj.Metadata["artifact-class"], "artifact-class metadata %q — the classification must be readable without a decrypt", obj.Metadata["artifact-class"])
}

// The payload is scrubbed before sealing, and the identifiers that make it a graph survive.
func TestPayloadIsScrubbedAndTheGraphSurvives(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl",
		`{"type":"user","uuid":"u1","parentUuid":null,"sessionId":"s1","cwd":"/Users/jane/work",`+
			`"message":{"content":[{"type":"text","text":"key ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}}`+"\n")

	f.run()
	obj, _ := f.port.get(f.port.keys()[0])
	m, payload, err := transforms.Open(obj.Body, f.unit.Identity)
	require.NoError(t, err)

	assert.NotContains(t, string(payload), "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "the secret reached the sink")
	assert.Contains(t, string(payload), `"uuid":"u1"`, "an exempt identifier was redacted; the graph would not reassemble")
	assert.Truef(t, m.Redaction != nil && m.Redaction.RuleHits["github-pat"] == 1, "the redaction ledger should record the rule: %+v", m.Redaction)
	assert.True(t, m.Redaction.Density > 0, "density should be recorded: it is the rule-drift alarm")
}

// A bounded run must report that it was bounded: silent truncation reads as "everything is
// collected". Progress must stream every decided file while the run is still going.
func TestProgressStreamsEveryDecidedFile(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/a.jsonl", line1)
	f.writeTranscript("p/b.jsonl", line1)

	type event struct {
		done, total int
		decision    auditlog.Decision
	}
	var events []event
	o := f.opts()
	o.Progress = func(sourceID string, done, total int, fo engine.FileOutcome) {
		assert.Equalf(t, "claude-code-transcripts", sourceID, "progress reported source %q", sourceID)
		events = append(events, event{done, total, fo.Decision})
	}
	if _, err := engine.Run(context.Background(), f.store, o); err != nil {
		t.Fatal(err)
	}

	require.Lenf(t, events, 2, "expected 2 progress events, got %d", len(events))
	for i, ev := range events {
		assert.Truef(t, ev.done == i+1 && ev.total == 2, "event %d: counter [%d/%d], want [%d/2]", i, ev.done, ev.total, i+1)
		assert.Equalf(t, auditlog.DecisionShipped, ev.decision, "event %d: decision %q, want shipped", i, ev.decision)
	}

	// Unchanged files stream too, or the counter could never reach its total.
	events = nil
	if _, err := engine.Run(context.Background(), f.store, o); err != nil {
		t.Fatal(err)
	}
	require.Lenf(t, events, 2, "steady-state run: expected 2 progress events, got %d", len(events))
	for i, ev := range events {
		assert.Equalf(t, auditlog.DecisionUnchanged, ev.decision, "steady-state event %d: decision %q, want unchanged", i, ev.decision)
	}
}

func TestHealthIsReportedPerSource(t *testing.T) {
	f := newFixture(t)
	// Root exists, nothing matches.
	require.NoError(t, os.MkdirAll(filepath.Join(f.home, ".claude", "projects"), 0o700))

	rep := f.run()
	require.Lenf(t, rep.Sources, 1, "expected 1 source, got %d", len(rep.Sources))
	assert.Equalf(t, sources.RootPresentNoMatch, rep.Sources[0].Health, "health %q, want root_present_no_match", rep.Sources[0].Health)
	assert.NotEqual(t, "", rep.Sources[0].Reason, "a non-collected health state must carry a reason")
}

// Every object an install writes must sit under ONE install root: mirror keys and the heartbeat
// once disagreed about the organization, and erasure is one prefix sweep that cannot cover two.
func TestEveryKeySitsUnderOneInstallRoot(t *testing.T) {
	f := newFixture(t)
	f.eff.OrganizationID = "acme"
	f.writeTranscript("p/s1.jsonl", line1)

	require.NotEqual(t, 0, f.run().Shipped)

	root, err := formats.InstallRoot(f.eff.OrganizationID, f.unit.InstallID.String())
	require.NoError(t, err)
	keys := f.port.keys()
	require.NotEqual(t, 0, len(keys), "no keys written")
	for _, k := range keys {
		assert.Truef(t, strings.HasPrefix(k, root+"/"), "key outside this install's root %s:\n  %s", root, k)
	}
}

// Object metadata must carry the integrity hash, not an empty string: only the manifest Seal
// returns has the ShippedHash it computed, so the engine must build metadata from that copy.
func TestObjectMetadataCarriesTheIntegrityHash(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.run()

	require.NotEqual(t, 0, len(f.port.keys()), "nothing shipped")
	for _, k := range f.port.keys() {
		obj, _ := f.port.get(k)
		got := obj.Metadata["shipped-hash"]
		if got == "" {
			t.Errorf("%s: shipped-hash is empty in object metadata", k)
			continue
		}
		// It must describe the payload actually sealed, which the manifest inside states too.
		m, _, err := transforms.Open(obj.Body, f.unit.Identity)
		require.NoError(t, err)
		assert.Equalf(t, m.ShippedHash, got, "%s: metadata shipped-hash %s disagrees with the sealed manifest's %s", k, got, m.ShippedHash)
	}
}
