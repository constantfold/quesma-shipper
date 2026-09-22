package config

import (
	"cmp"
	"errors"
	"slices"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// Resolve merges the layers, records provenance, and enforces every limit.
func Resolve(in Input) (*Effective, error) {
	if in.Catalog == nil {
		return nil, errors.New("config: no compiled catalog")
	}

	eff := &Effective{
		ConfigVersion:  0,
		OrganizationID: "default",
		Schedule:       "15m",
		MaxFilesPerRun: 512,
		DrainDeadline:  5 * time.Minute,
		StateDir:       in.StateDir,
		ConfigExpired:  in.ConfigExpired,
		Catalog:        in.Catalog,
		RulePacks:      []string{"gitleaks-core", "quesma-extra", "cloud-keys", "generic-entropy", "pii-core"},
		// Without the compiled exemption baseline the entropy backstop shreds the join keys that make a trajectory a graph.
		StructuralEx:            transforms.CompiledExemptions(),
		IncludeInstallRecipient: true,
		AutoupdateEnabled:       true,
		Provenance:              map[string]Origin{},
	}
	// Defaults are attributed too, so provenance never has a blank origin column.
	for _, k := range []string{"mode.schedule", "max_files_per_run",
		"send.sink", "scrub.rule_packs", "state_dir", "upload_targets", "config_version",
		"drain_deadline", "structural_exempt",
		"encryption.additional_recipients", "encryption.include_install_recipient",
		"autoupdate.enabled"} {
		eff.setOrigin(k, LayerCompiledDefaults)
	}

	// Source defaults come from the catalog, which is why it is layer 2.
	overrides := map[string][]layeredOverride{}
	for _, s := range in.Catalog.Sources() {
		eff.Sources = append(eff.Sources, ResolvedSource{
			Source:  s,
			Enabled: s.IsEnabledByDefault(),
		})
		eff.setOrigin("sources."+s.ID+".enabled", LayerBundledCatalog)
		eff.setOrigin("sources."+s.ID+".include", LayerBundledCatalog)
		eff.setOrigin("sources."+s.ID+".roots", LayerBundledCatalog)
	}

	// --- merge, lowest layer first ------------------------------------------
	for _, ld := range in.Layers {
		if ld.Doc == nil {
			continue
		}
		// The envelope describes the control plane's own issuing event, so a local file carrying it is a typo or a relabeling attempt.
		if ld.Doc.IssuedAt != nil || ld.Doc.Org != nil {
			if ld.Layer != LayerRemote {
				return nil, &RejectionError{ld.Layer, "issued_at / org",
					"only the served remote config carries the served envelope: these fields " +
						"describe the org's issuing event and its key namespace, not machine configuration"}
			}
			if ld.Doc.Org != nil && *ld.Doc.Org != "" {
				eff.OrganizationID = *ld.Doc.Org
				eff.setOrigin("organization", ld.Layer)
			}
		}

		if rej := applyDocument(eff, ld); rej != nil {
			return nil, rej
		}

		for _, o := range ld.Doc.Sources {
			if _, ok := in.Catalog.Source(o.ID); !ok {
				return nil, &RejectionError{ld.Layer, "sources." + o.ID,
					"no such source in the compiled catalog: a config layer cannot create a source, only adjust one"}
			}
			overrides[o.ID] = append(overrides[o.ID], layeredOverride{ld.Layer, o})
		}
	}

	if err := applySourceOverrides(eff, overrides); err != nil {
		return nil, err
	}

	for _, check := range []func(*Effective) error{checkConfigVersion, checkUploadTargets, checkRulePacks, checkEncryption} {
		if err := check(eff); err != nil {
			return nil, err
		}
	}

	eff.Deny = sources.New(in.Env.Home)

	if err := resolveRoots(eff, in); err != nil {
		return nil, err
	}

	slices.SortFunc(eff.Sources, func(a, b ResolvedSource) int { return cmp.Compare(a.ID, b.ID) })
	return eff, nil
}
