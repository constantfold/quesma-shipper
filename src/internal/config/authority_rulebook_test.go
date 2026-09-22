package config_test

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"

	protocol "github.com/QuesmaOrg/shipper-protocol"
)

// The authority rulebook in the shipper-protocol module bounds a served config's authority; this file makes it executable, and a row without a probe fails.

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

func rulebookProbes() map[string]rulebookProbe {
	return map[string]rulebookProbe{
		"issued_at / org": {custom: func(t *testing.T) {
			envelope := "issued_at: \"2026-08-12T00:00:00Z\"\norg: acme\n"
			assert.Equal(t, "acme", resolved(t, fakeHome(t), remote(t, envelope)).OrganizationID)
			// A local org would relabel where this machine writes.
			for _, y := range []string{envelope, "org: acme\n", "issued_at: 2026-01-01T00:00:00Z\n"} {
				_, err := resolve(t, fakeHome(t), user(t, y))
				mustReject(t, err, "issued_at / org")
			}
		}},

		"config_version": {
			accept: "config_version: 1\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equal(t, 1, eff.ConfigVersion)
				assert.Equal(t, config.LayerRemote, eff.Provenance["config_version"].Layer)
			},
			reject: "config_version: 99\n",
		},

		"mode.schedule": {
			accept: "mode:\n  schedule: \"5m\"\n",
			verify: func(t *testing.T, eff *config.Effective) { assert.Equal(t, "5m", eff.Schedule) },
		},

		"max_files_per_run": {
			accept: "max_files_per_run: 32\n",
			verify: func(t *testing.T, eff *config.Effective) { assert.Equal(t, 32, eff.MaxFilesPerRun) },
		},

		"drain_deadline": {
			accept: "drain_deadline: 2h\n",
			verify: func(t *testing.T, eff *config.Effective) { assert.Equal(t, 2*time.Hour, eff.DrainDeadline) },
			reject: "drain_deadline: -5m\n",
		},

		// A served config that could move the state directory would silently defeat a pause.
		"state_dir": {reject: "state_dir: /var/lib/shipper\n", custom: func(t *testing.T) {
			_, err := resolve(t, fakeHome(t), remote(t, "state_dir: /tmp/somewhere-else\n"))
			mustReject(t, err, "state_dir")
			// The machine owner's own file must still set it, or the field is settable by nobody.
			assert.Equal(t, "/tmp/mine", resolved(t, fakeHome(t), user(t, "state_dir: /tmp/mine\n")).StateDir)
		}},

		"upload_targets": {
			reject: "upload_targets:\n  - origin: https://evil.example.com\n    addressing: virtual-hosted\n",
			custom: func(t *testing.T) {
				eff := resolved(t, fakeHome(t), user(t, "upload_targets:\n  - origin: https://acme.s3.example.com\n    addressing: virtual-hosted\n"))
				require.Len(t, eff.UploadTargets, 1)
				assert.Equal(t, "https://acme.s3.example.com", eff.UploadTargets[0].Origin)
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
					assert.Contains(t, eff.RulePacks, floor)
				}
			},
			reject: "scrub:\n  rule_packs:\n    - no-such-pack\n",
		},

		"scrub.secret_key_names": {custom: func(t *testing.T) {
			eff := resolved(t, fakeHome(t),
				user(t, "scrub:\n  secret_key_names:\n    - HOUSE_SIG\n"),
				remote(t, "scrub:\n  secret_key_names:\n    - ACME_DEPLOY_TOKEN\n"))
			assert.Equal(t, []string{"HOUSE_SIG", "ACME_DEPLOY_TOKEN"}, eff.SecretKeyNames)
		}},

		"structural_exempt": {
			accept: "structural_exempt:\n  claude-code: [acmeInternalTraceId]\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Contains(t, eff.StructuralEx["claude-code"], "acmeInternalTraceId")
				for k, compiled := range transforms.CompiledExemptions() {
					for _, p := range compiled {
						assert.Contains(t, eff.StructuralEx[k], p, "served exemptions displaced the compiled baseline")
					}
				}
			},
		},

		"encryption.additional_recipients": {custom: func(t *testing.T) {
			eff := resolved(t, fakeHome(t),
				user(t, "encryption:\n  additional_recipients: ["+probeRecipientA+"]\n"),
				remote(t, "encryption:\n  additional_recipients: ["+probeRecipientB+", "+probeRecipientA+"]\n"))
			// Union in first-seen order, no duplicates; not mentioning include_install_recipient keeps it.
			assert.Equal(t, []string{probeRecipientA, probeRecipientB}, eff.AdditionalRecipients)
			assert.Equal(t, config.LayerRemote, eff.Provenance["encryption.additional_recipients"].Layer)
			assert.True(t, eff.IncludeInstallRecipient)
		}},

		"encryption.include_install_recipient": {
			accept: "encryption:\n  include_install_recipient: false\n  additional_recipients:\n    - " + probeRecipientA + "\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.False(t, eff.IncludeInstallRecipient)
				assert.Equal(t, []string{probeRecipientA}, eff.AdditionalRecipients)
			},
			// Withhold with no reader would seal objects no key can open.
			reject: "encryption:\n  include_install_recipient: false\n",
		},

		"sources[].enabled": {
			accept: "sources:\n  - id: claude-code-transcripts\n    enabled: false\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.False(t, sourceByID(t, eff, "claude-code-transcripts").Enabled)
			},
			custom: func(t *testing.T) {
				eff := resolved(t, fakeHome(t),
					user(t, "sources:\n  - id: claude-code-transcripts\n    enabled: false\n"),
					remote(t, "sources:\n  - id: claude-code-transcripts\n    enabled: true\n"))
				assert.False(t, sourceByID(t, eff, "claude-code-transcripts").Enabled, "a remote enable must not undo a local disable")
			},
		},

		"sources[].roots / include / exclude": {
			accept: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/.claude\"]\n    include: [\"projects/**/*.jsonl\"]\n    exclude: [\"projects/**/tmp/*\"]\n",
			verify: func(t *testing.T, eff *config.Effective) {
				src := sourceByID(t, eff, "claude-code-transcripts")
				assert.Equal(t, ".claude", filepath.Base(src.Root), src.RootUnresolvedReason)
				assert.Equal(t, []string{"projects/**/*.jsonl"}, src.Include)
			},
			reject: "sources:\n  - id: claude-code-transcripts\n    roots: [\"~/elsewhere\"]\n",
		},

		"sources[].max_file_bytes": {
			accept: "sources:\n  - id: claude-code-transcripts\n    max_file_bytes: 1024\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.Equal(t, int64(1024), sourceByID(t, eff, "claude-code-transcripts").MaxFileBytes)
			},
		},

		"sources[].enrichers{}": {
			accept: "sources:\n  - id: cursor-transcripts\n    enrichers:\n      cursor-transcript-join: false\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.False(t, sourceByID(t, eff, "cursor-transcripts").Enrichers["cursor-transcript-join"])
			},
			reject: "sources:\n  - id: cursor-transcripts\n    enrichers:\n      exfiltrate-everything: true\n",
		},

		"a source id not in the compiled catalog": {reject: "sources:\n  - id: no-such-source\n    enabled: false\n"},

		// The probe uses the document a pre-removal control plane serves: older clients still honor the disable.
		"crash_report.enabled / dsn": {
			accept: "crash_report:\n  enabled: false\n  dsn: https://key@example.com/1\n",
			verify: func(t *testing.T, eff *config.Effective) {
				assert.NotContains(t, eff.Provenance, "crash_report.enabled", "an ignored field was attributed")
			},
		},

		"autoupdate.enabled": {
			accept: "autoupdate:\n  enabled: false\n",
			verify: func(t *testing.T, eff *config.Effective) { assert.False(t, eff.AutoupdateEnabled) },
			reject: "autoupdate:\n  enabled: true\n",
		},
	}
}

func TestRulebookMatchesResolver(t *testing.T) {
	raw, err := fs.ReadFile(protocol.FS, "authority.json")
	require.NoError(t, err)
	var rb struct {
		Classes map[string]string `json:"classes"`
		Fields  []struct {
			Field     string `json:"field"`
			ServerMay string `json:"server_may"`
		} `json:"fields"`
	}
	require.NoError(t, json.Unmarshal(raw, &rb))
	probes := rulebookProbes()
	for _, f := range rb.Fields {
		probe, ok := probes[f.Field]
		delete(probes, f.Field)
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
			accept, reject, custom := probe.accept != "", probe.reject != "", probe.custom != nil
			shapes := map[string]bool{
				"refused":  !accept && (reject || custom),
				"set":      accept || custom,
				"union":    accept || custom,
				"off-only": accept && reject || custom,
				"envelope": custom,
				// An ignored row is a tolerance claim: the document must LOAD and the field must change nothing.
				"ignored": accept && !reject,
			}
			require.True(t, shapes[f.ServerMay], "probe shape does not fit a %s row", f.ServerMay)
			if accept {
				eff, err := resolve(t, fakeHome(t), remote(t, probe.accept))
				require.NoError(t, err, "the served document must be allowed to touch this field")
				if probe.verify != nil {
					probe.verify(t, eff)
				}
			}
			if reject {
				_, err := resolve(t, fakeHome(t), remote(t, probe.reject))
				mustReject(t, err, "")
			}
			if custom {
				probe.custom(t)
			}
		})
	}
	assert.Empty(t, probes, "these probes have no row in the shipper-protocol authority rulebook")
}
