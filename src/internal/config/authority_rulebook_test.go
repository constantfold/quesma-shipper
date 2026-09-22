package config_test

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"

	protocol "github.com/QuesmaOrg/shipper-protocol"
)

// The authority rulebook in the shipper-protocol module bounds a served config's authority; this file makes it executable, and a row without a probe fails.

type rulebookField struct {
	Field     string `json:"field"`
	ServerMay string `json:"server_may"`
}

type rulebookDoc struct {
	Classes map[string]string `json:"classes"`
	Fields  []rulebookField   `json:"fields"`
}

// rulebookProbe exercises one row: accept must apply, reject must be refused, custom covers the asymmetries.
type rulebookProbe struct {
	accept string
	verify func(*testing.T, *config.Effective)
	reject string
	custom func(*testing.T)
}

const (
	probeRecipientA = "age1cpx4grz9j4fkn36cfurggwcg4l0da5fyqadl8fwagtcwy55gt44qlclfa5"
	probeRecipientB = "age14lz0mm7uh45zqavz3pxe89dauhn2e3p7mlu6ve0gt8zhrz2j3ahsz8kf7p"
)

func resolveLayers(t *testing.T, layers ...config.LayeredDocument) (*config.Effective, error) {
	t.Helper()
	return config.Resolve(baseInput(t, fakeHome(t), layers...))
}

func served(t *testing.T, y string) config.LayeredDocument {
	t.Helper()
	return servedLayer(t, config.LayerRemote, y)
}

func mustReject(t *testing.T, err error, context string) {
	t.Helper()
	var rej *config.RejectionError
	require.ErrorAsf(t, err, &rej, "%s: failed with %v, want a *RejectionError", context, err)
}

func rulebookProbes() map[string]rulebookProbe {
	return map[string]rulebookProbe{
		"issued_at / org": {custom: func(t *testing.T) {
			envelope := "issued_at: \"2026-08-12T00:00:00Z\"\norg: acme\n"
			eff, err := resolveLayers(t, served(t, envelope))
			require.NoErrorf(t, err, "served envelope refused: %v", err)
			assert.Equalf(t, "acme", eff.OrganizationID, "served org did not become the organization id: %q", eff.OrganizationID)
			_, err = resolveLayers(t, layerDoc(t, config.LayerUser, envelope))
			mustReject(t, err, "envelope in a local file")
		}},

		"config_version": {
			accept: "config_version: 1\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equalf(t, 1, eff.ConfigVersion, "config_version %d, want 1", eff.ConfigVersion)
				assert.Equal(t, config.LayerRemote, eff.Provenance["config_version"].Layer)
			},
			reject: "config_version: 99\n",
		},

		"mode.schedule": {
			accept: "mode:\n  schedule: \"5m\"\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equalf(t, "5m", eff.Schedule, "schedule %q", eff.Schedule)
			},
		},

		"max_files_per_run": {
			accept: "max_files_per_run: 32\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equalf(t, 32, eff.MaxFilesPerRun, "max_files_per_run %d", eff.MaxFilesPerRun)
			},
		},

		"drain_deadline": {
			accept: "drain_deadline: 2h\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equalf(t, 2*time.Hour, eff.DrainDeadline, "drain_deadline %v", eff.DrainDeadline)
			},
			reject: "drain_deadline: -5m\n",
		},

		"state_dir": {reject: "state_dir: /var/lib/shipper\n"},

		"upload_targets": {
			reject: "upload_targets:\n  - origin: https://evil.example.com\n    addressing: virtual-hosted\n",
			custom: func(t *testing.T) {
				// The machine owner's own layer is the one that may name a destination.
				eff, err := resolveLayers(t, layerDoc(t, config.LayerUser, "upload_targets:\n  - origin: https://acme.s3.example.com\n    addressing: virtual-hosted\n"))
				require.NoErrorf(t, err, "local upload_targets refused: %v", err)
				require.Truef(t, len(eff.UploadTargets) == 1 && eff.UploadTargets[0].Origin == "https://acme.s3.example.com", "local allowlist did not apply: %+v", eff.UploadTargets)
				assert.Equal(t, config.LayerUser, eff.Provenance["upload_targets"].Layer)
			},
		},

		// The probe uses the s3 document a pre-vend control plane serves: one served document has to work for both fleets.
		"send.sink / bucket / prefix / region / path": {
			accept: "send:\n  sink: s3\n  bucket: acme-archive\n  prefix: teams/acme\n  region: eu-central-1\n  path: /var/tmp/out\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equal(t, config.LayerCompiledDefaults, eff.Provenance["send.sink"].Layer)
			},
		},

		"scrub.rule_packs": {
			accept: "scrub:\n  rule_packs:\n    - gitleaks-core\n",
			verify: func(t *testing.T, eff *config.Effective) {
				// A served subset must not remove the compiled floor: union only adds.
				for _, floor := range []string{"gitleaks-core", "quesma-extra", "cloud-keys", "generic-entropy", "pii-core"} {
					assert.Truef(t, slices.Contains(eff.RulePacks, floor), "served rule_packs removed compiled pack %s: union must only add", floor)
				}
			},
			reject: "scrub:\n  rule_packs:\n    - no-such-pack\n",
		},

		"scrub.secret_key_names": {custom: func(t *testing.T) {
			eff, err := resolveLayers(t,
				layerDoc(t, config.LayerUser, "scrub:\n  secret_key_names:\n    - HOUSE_SIG\n"),
				served(t, "scrub:\n  secret_key_names:\n    - ACME_DEPLOY_TOKEN\n"),
			)
			require.NoError(t, err)
			for _, name := range []string{"HOUSE_SIG", "ACME_DEPLOY_TOKEN"} {
				assert.Truef(t, slices.Contains(eff.SecretKeyNames, name), "union lost %s: %v", name, eff.SecretKeyNames)
			}
		}},

		"structural_exempt": {
			accept: "structural_exempt:\n  claude-jsonl:\n    - message.id\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.True(t, slices.Contains(eff.StructuralEx["claude-jsonl"], "message.id"), "served exemption did not merge")
				for k := range transforms.CompiledExemptions() {
					if _, ok := eff.StructuralEx[k]; !ok {
						t.Errorf("served exemptions replaced the compiled baseline: %s gone", k)
					}
				}
			},
		},

		"encryption.additional_recipients": {custom: func(t *testing.T) {
			eff, err := resolveLayers(t,
				layerDoc(t, config.LayerUser, "encryption:\n  additional_recipients:\n    - "+probeRecipientA+"\n"),
				served(t, "encryption:\n  additional_recipients:\n    - "+probeRecipientB+"\n"),
			)
			require.NoError(t, err)
			for _, r := range []string{probeRecipientA, probeRecipientB} {
				assert.Truef(t, slices.Contains(eff.AdditionalRecipients, r), "union lost recipient %s", r)
			}
		}},

		"encryption.include_install_recipient": {
			accept: "encryption:\n  include_install_recipient: false\n  additional_recipients:\n    - " + probeRecipientA + "\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.True(t, !eff.IncludeInstallRecipient, "served withhold did not apply")
			},
			// Withhold with no reader would seal objects no key can open.
			reject: "encryption:\n  include_install_recipient: false\n",
		},

		"sources[].enabled": {
			accept: "sources:\n  - id: claude-code-transcripts\n    enabled: false\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.True(t, !sourceByID(t, eff, "claude-code-transcripts").Enabled, "served disable did not apply")
			},
			// The asymmetry on this field is pinned by TestLocalDenyBeatsRemoteAllow in resolve_test.go.
		},

		"sources[].roots / include / exclude": {
			accept: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/.claude\"]\n    include: [\"projects/**/*.jsonl\"]\n    exclude: [\"projects/**/tmp/*\"]\n",
			verify: func(t *testing.T, eff *config.Effective) {
				src := sourceByID(t, eff, "claude-code-transcripts")
				assert.Equalf(t, ".claude", filepath.Base(src.Root), "root did not resolve within the served candidate: %q (%s)", src.Root, src.RootUnresolvedReason)
				assert.Truef(t, slices.Equal(src.Include, []string{"projects/**/*.jsonl"}), "include %v", src.Include)
			},
			reject: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/elsewhere\"]\n",
		},

		"sources[].max_file_bytes": {
			accept: "sources:\n  - id: claude-code-transcripts\n    max_file_bytes: 1024\n",
			verify: func(t *testing.T, eff *config.Effective) {
				src := sourceByID(t, eff, "claude-code-transcripts")
				assert.Equalf(t, int64(1024), src.MaxFileBytes, "max_file_bytes %d", src.MaxFileBytes)
			},
		},

		"sources[].enrichers{}": {
			accept: "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: false\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.True(t, !sourceByID(t, eff, "cursor-transcripts").Enrichers["cursor-transcript-join"], "served enricher disable did not apply")
			},
			reject: "sources:\n  - id: cursor-transcripts\n    enrichers:\n      exfiltrate-everything: true\n",
			custom: func(t *testing.T) {
				// A served enable over a local disable is ignored, not honored.
				eff := resolved(t, fakeHome(t),
					layerDoc(t, config.LayerUser, "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: false\n"),
					served(t, "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: true\n"),
				)
				assert.True(t, !sourceByID(t, eff, "cursor-transcripts").Enrichers["cursor-transcript-join"], "served enable overrode a local enricher disable")
			},
		},

		"a source id not in the compiled catalog": {reject: "sources:\n  - id: no-such-source\n    enabled: false\n"},

		// The probe uses the document a pre-removal control plane serves: older clients still honor the disable.
		"crash_report.enabled / dsn": {
			accept: "crash_report:\n  enabled: false\n  dsn: https://key@example.com/1\n",
			verify: func(t *testing.T, eff *config.Effective) {
				if _, set := eff.Provenance["crash_report.enabled"]; set {
					t.Error("an ignored field was attributed: crash reporting is removed")
				}
			},
		},

		"autoupdate.enabled": {
			accept: "autoupdate:\n  enabled: false\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.True(t, !eff.AutoupdateEnabled, "served autoupdate disable did not apply")
			},
			reject: "autoupdate:\n  enabled: true\n",
		},
	}
}

func loadRulebook(t *testing.T) rulebookDoc {
	t.Helper()
	raw, err := fs.ReadFile(protocol.FS, "authority.json")
	require.NoErrorf(t, err, "read authority.json: %v", err)
	var rb rulebookDoc
	require.NoError(t, json.Unmarshal(raw, &rb))
	return rb
}

func TestRulebookMatchesResolver(t *testing.T) {
	rb := loadRulebook(t)
	probes := rulebookProbes()

	documented := map[string]bool{}
	for _, f := range rb.Fields {
		documented[f.Field] = true
	}
	for name := range probes {
		assert.Truef(t, documented[name], "probe %q has no row in the shipper-protocol authority rulebook", name)
	}

	for _, f := range rb.Fields {
		probe, ok := probes[f.Field]
		if !ok {
			t.Errorf("rulebook row %q has no probe: the row is documentation, not contract", f.Field)
			continue
		}
		if _, known := rb.Classes[f.ServerMay]; !known {
			t.Errorf("row %q uses undeclared class %q", f.Field, f.ServerMay)
			continue
		}
		t.Run(f.Field, func(t *testing.T) {
			// The class dictates the probe's shape, so a row reclassified in the JSON without a behavior change fails here.
			switch f.ServerMay {
			case "refused":
				require.Truef(t, probe.accept == "" && (probe.reject != "" || probe.custom != nil), "a refused row needs a reject probe and no accept probe")
			case "set", "union":
				if probe.accept == "" && probe.custom == nil {
					t.Fatalf("a %s row needs an accept probe", f.ServerMay)
				}
			case "off-only":
				require.Truef(t, probe.accept != "" && probe.reject != "" || probe.custom != nil, "an off-only row needs both an accept (disable) and a reject (enable) probe")
			case "envelope":
				require.Truef(t, probe.custom != nil, "the envelope row needs a custom probe")
			case "ignored":
				// An ignored row is a tolerance claim: the document must LOAD and the field must change nothing.
				require.Truef(t, probe.accept != "" && probe.reject == "", "an ignored row needs an accept probe and no reject probe")
			}
			if probe.accept != "" {
				eff, err := resolveLayers(t, served(t, probe.accept))
				require.NoErrorf(t, err, "the served document must be allowed to touch this field: %v", err)
				if probe.verify != nil {
					probe.verify(t, eff)
				}
			}
			if probe.reject != "" {
				_, err := resolveLayers(t, served(t, probe.reject))
				mustReject(t, err, "served document")
			}
			if probe.custom != nil {
				probe.custom(t)
			}
		})
	}
}
