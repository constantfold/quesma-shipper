package config_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// A user layer disabling a source beats a remote layer enabling it.
func TestLocalDenyBeatsRemoteAllow(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    enabled: false
`)},
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    enabled: true
`)},
	))
	require.NoError(t, err)
	for _, s := range eff.Sources {
		require.True(t, s.ID != "claude-code-transcripts" || !s.Enabled, "a remote enable must not undo a local disable")
	}
}

// The control plane's served document in the exact shape renderConfig composes it. This is the
// cross-repo contract: a field here that starts being refused makes the client refuse the WHOLE
// document and fall back to its cached config, so the server must stop serving it first. The
// send: block is the s3 one still served to the pre-vend fleet and has to keep LOADING here.
func TestServedDocumentWithAuthoredPartResolves(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, `
issued_at: 2026-08-12T10:00:00Z
org: acme
send:
  sink: s3
  bucket: acme-archive
  region: eu-central-1
encryption:
  additional_recipients:
    - age1rqcz770l8nugps6nxpz8lwgcrcqkcrz982jf6z6mjqlkvx6rgcssz7h2ys
mode:
  schedule: "30m"
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
scrub:
  rule_packs: [gitleaks-core]
max_files_per_run: 200
`)},
	))
	require.NoErrorf(t, err, "the served document must resolve: %v", err)
	assert.Equalf(t, "30m", eff.Schedule, "mode.schedule = %q: the org's schedule did not take effect", eff.Schedule)
	assert.Equalf(t, 200, eff.MaxFilesPerRun, "max_files_per_run = %d, want 200", eff.MaxFilesPerRun)
	assert.Equal(t, config.LayerRemote, eff.Provenance["mode.schedule"].Layer)
}

// A layer's exemptions MERGE with the compiled baseline rather than replacing it; detection rules are free to add.
func TestServedExemptionsMergeWithTheCompiledBaseline(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
structural_exempt:
  claude-code: [acmeInternalTraceId]
`)},
	))
	require.NoErrorf(t, err, "the served layer may carry exemptions: %v", err)
	if !slices.Contains(eff.StructuralEx["claude-code"], "acmeInternalTraceId") {
		t.Errorf("served exemption not applied: %v", eff.StructuralEx)
	}
	for _, compiled := range transforms.CompiledExemptions()["claude-code"] {
		assert.Truef(t, slices.Contains(eff.StructuralEx["claude-code"], compiled), "served addition displaced compiled exemption %q", compiled)
	}
}

// A clone-and-run install must come up with the compiled exemption baseline already in force.
// Asserted by name so a future trim of CompiledExemptions cannot silently drop a join key
// and keep this test green.
func TestCompiledExemptionBaselineIsSeededByDefault(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	for _, p := range []string{"toolUseId", "message.content[].id", "message.content[].tool_use_id"} {
		assert.Truef(t, slices.Contains(eff.StructuralEx["claude-code"], p), "claude-code join key %q not exempt by default", p)
	}
}

// Union, not replace: a layer naming one real pack must not drop the four the defaults carry.
func TestRulePacksUnionRatherThanReplace(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
scrub:
  rule_packs: [pii-core]
`)},
	))
	require.NoError(t, err)
	for _, want := range []string{"gitleaks-core", "cloud-keys", "generic-entropy", "pii-core"} {
		found := false
		for _, got := range eff.RulePacks {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("rule pack %q missing from %v", want, eff.RulePacks)
		}
	}
}

// The served config names the organization; it cannot name the write path, so the send block it serves is ignored.
func TestServedRemoteConfigSetsOrgAndIgnoresTheSendBlock(t *testing.T) {
	home := fakeHome(t)
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, `
org: acme
send:
  sink: s3
  bucket: acme-archive
  region: eu-central-1
`)},
	))
	require.NoErrorf(t, err, "the served config must resolve: %v", err)
	assert.Equalf(t, "acme", eff.OrganizationID, "served config not applied: %s", eff.OrganizationID)
}

// Envelope fields are refused from any layer but the remote one: a local org would relabel where this machine writes.
func TestEnvelopeFieldsAreRefusedFromLocalLayers(t *testing.T) {
	home := fakeHome(t)
	for _, y := range []string{"org: acme\n", "issued_at: 2026-01-01T00:00:00Z\n"} {
		_, err := config.Resolve(baseInput(t, home,
			config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, y)},
		))
		var rej *config.RejectionError
		if !errors.As(err, &rej) {
			t.Errorf("a user layer set %q and it was accepted: %v", strings.TrimSpace(y), err)
		}
	}
}

// Standalone writes organization=default; an enterprise install takes its organization from the served config.
func TestOrganizationComesFromServedConfigNotAConstant(t *testing.T) {
	home := fakeHome(t)

	standalone, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)
	assert.Equalf(t, "default", standalone.OrganizationID, "standalone organization %q, want default", standalone.OrganizationID)

	enterprise, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, "org: acme\n")},
	))
	require.NoError(t, err)
	assert.Equalf(t, "acme", enterprise.OrganizationID, "enterprise organization %q, want acme", enterprise.OrganizationID)
}

// The two parse paths on one document: a served document may carry fields this build does not know, the local file may not.
func TestServedParseToleratesUnknownFieldsAndTheLocalParseDoesNot(t *testing.T) {
	home := fakeHome(t)
	const body = "config_version: 1\n" +
		"send:\n  sink: s3\n  bucket: acme-archive\n" +
		"future_top_level: 7\n" +
		"mode:\n  schedule: \"5m\"\n  future_nested: yes\n"

	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: servedDoc(t, body)},
	))
	require.NoErrorf(t, err, "a served document with unknown fields must resolve: %v", err)
	assert.Equalf(t, "5m", eff.Schedule, "the fields this build does know must still apply: schedule %q", eff.Schedule)

	if _, err := config.ParseDocument([]byte(body)); err == nil {
		t.Fatal("the strict local parse accepted a field this build does not know")
	}
}

// A config push touching only a redaction rule and the run budget must invalidate no fingerprints.
func TestSpecFingerprintCoversOnlyReadAffectingFields(t *testing.T) {
	home := fakeHome(t)

	before, err := config.Resolve(baseInput(t, home))
	require.NoError(t, err)

	// A push that changes a redaction rule and the run budget.
	unrelated, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote, Doc: doc(t, `
scrub:
  rule_packs: [pii-core]
max_files_per_run: 8
`)},
	))
	require.NoError(t, err)
	for i := range before.Sources {
		assert.Equal(t, before.Sources[i].SpecFingerprint, unrelated.Sources[i].SpecFingerprint)
	}

	// A glob change resets exactly one source.
	globbed, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, `
sources:
  - id: claude-code-transcripts
    include: ["projects/**/*.jsonl"]
`)},
	))
	require.NoError(t, err)
	changed := 0
	for i := range before.Sources {
		if before.Sources[i].SpecFingerprint != globbed.Sources[i].SpecFingerprint {
			changed++
			assert.Equalf(t, "claude-code-transcripts", before.Sources[i].ID, "%s: an unrelated source's fingerprint changed", before.Sources[i].ID)
		}
	}
	assert.Equalf(t, 1, changed, "a glob change should reset exactly one source, reset %d", changed)
}

// state_dir is machine-owner only: a served config that could move it would silently defeat a pause.
func TestTheServedDocumentCannotMoveTheStateDirectory(t *testing.T) {
	home := fakeHome(t)
	_, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerRemote,
			Doc: doc(t, "state_dir: /tmp/somewhere-else\n")},
	))
	var rej *config.RejectionError
	require.ErrorAsf(t, err, &rej, "the served document moved the state directory: %v", err)
	assert.Equalf(t, "state_dir", rej.Field, "rejected the wrong field: %s", rej.Field)
}

func TestTheUserLayerMayMoveTheStateDirectory(t *testing.T) {
	home := fakeHome(t)
	// The machine owner's own file must still set it, or the field is settable by nobody.
	eff, err := config.Resolve(baseInput(t, home,
		config.LayeredDocument{Layer: config.LayerUser, Doc: doc(t, "state_dir: /tmp/mine\n")},
	))
	require.NoError(t, err)
	assert.Equalf(t, "/tmp/mine", eff.StateDir, "state_dir = %q", eff.StateDir)
}
