package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/sources"
)

// applyDocument folds one layer into the effective config: narrowing is free, widening stays with the machine owner.
func applyDocument(eff *Effective, ld LayeredDocument) *RejectionError {
	d, l := ld.Doc, ld.Layer

	if len(d.StructuralEx) > 0 {
		// Merged, never replaced: a layer's additions must not strip the compiled join-key protections underneath them.
		eff.StructuralEx = mergeExemptions(eff.StructuralEx, d.StructuralEx)
		eff.setOrigin("structural_exempt", l)
	}
	setValue(eff, l, "config_version", &eff.ConfigVersion, d.ConfigVersion)
	if d.Mode != nil {
		setValue(eff, l, "mode.schedule", &eff.Schedule, d.Mode.Schedule)
	}
	setValue(eff, l, "max_files_per_run", &eff.MaxFilesPerRun, d.MaxFilesPerRun)
	if d.DrainDeadline != nil {
		v, err := time.ParseDuration(*d.DrainDeadline)
		if err != nil {
			return &RejectionError{l, "drain_deadline",
				fmt.Sprintf("%q is not a duration: %v", *d.DrainDeadline, err)}
		}
		if v <= 0 {
			return &RejectionError{l, "drain_deadline",
				"must be positive: a non-positive deadline makes every drain a no-op"}
		}
		eff.DrainDeadline = v
		eff.setOrigin("drain_deadline", l)
	}

	if d.Autoupdate != nil && d.Autoupdate.Enabled != nil {
		if *d.Autoupdate.Enabled && !l.IsLocal() {
			return &RejectionError{l, "autoupdate.enabled",
				"a non-local layer may turn self-update off but never on: re-enabling over a local refusal is a widen"}
		}
		eff.AutoupdateEnabled = *d.Autoupdate.Enabled
		eff.setOrigin("autoupdate.enabled", l)
	}
	if d.TelemetryEndpoint != nil {
		// The remote layer's alone: the value names a route on the control plane that serves it.
		if l.IsLocal() {
			return &RejectionError{l, "telemetry_endpoint",
				"served by the control plane only: it names a route on the control plane this install is enrolled with"}
		}
		endpoint := strings.TrimSpace(*d.TelemetryEndpoint)
		if endpoint != "" && !strings.HasPrefix(endpoint, "/") {
			return &RejectionError{l, "telemetry_endpoint",
				"must be a path beginning with /, resolved against the enrolled control-plane origin, never a URL"}
		}
		eff.TelemetryEndpoint = endpoint
		eff.setOrigin("telemetry_endpoint", l)
	}
	if d.StateDir != nil {
		if !l.IsLocal() {
			return &RejectionError{l, "state_dir",
				"machine-owner only: it holds the identity unit, the fingerprints and the pause state"}
		}
		eff.StateDir = *d.StateDir
		eff.setOrigin("state_dir", l)
	}
	if len(d.UploadTargets) > 0 {
		if !l.IsLocal() {
			return &RejectionError{l, "upload_targets",
				"machine-owner only: a presigned ticket authorizes itself, so this pin is the only control on destinations"}
		}
		// Replace rather than union: two layers each holding half an allowlist would mean no file says where this machine writes.
		eff.UploadTargets = slices.Clone(d.UploadTargets)
		eff.setOrigin("upload_targets", l)
	}

	// Union: another rule pack or key name only makes scrubbing stricter, and no layer may remove another's readers.
	if s := d.Scrub; s != nil {
		eff.mergeStrings(l, "scrub.rule_packs", &eff.RulePacks, s.RulePacks)
		eff.mergeStrings(l, "scrub.secret_key_names", &eff.SecretKeyNames, s.SecretKeyNames)
	}
	if en := d.Encryption; en != nil {
		eff.mergeStrings(l, "encryption.additional_recipients", &eff.AdditionalRecipients, en.AdditionalRecipients)
		setValue(eff, l, "encryption.include_install_recipient", &eff.IncludeInstallRecipient, en.IncludeInstallRecipient)
	}
	return nil
}

type layeredOverride struct {
	layer    Layer
	override SourceOverride
}

// applySourceOverrides folds per-source overrides in layer order; a non-local layer cannot undo a local disable.
func applySourceOverrides(eff *Effective, overrides map[string][]layeredOverride) error {
	for i := range eff.Sources {
		src := &eff.Sources[i]
		locallyDisabled := false
		// The enricher map is detached from the compiled catalog on first touch, once per source.
		clonedEnrichers := false

		for _, lo := range overrides[src.ID] {
			o := lo.override
			if o.Enabled != nil {
				if locallyDisabled && !lo.layer.IsLocal() && *o.Enabled {
					// A remote enable cannot undo a local disable.
					continue
				}
				src.Enabled = *o.Enabled
				eff.setOrigin("sources."+src.ID+".enabled", lo.layer)
				if !*o.Enabled && lo.layer.IsLocal() {
					locallyDisabled = true
				}
			}
			eff.replaceStrings(lo.layer, "sources."+src.ID+".roots", &src.Roots, o.Roots)
			eff.replaceStrings(lo.layer, "sources."+src.ID+".include", &src.Include, o.Include)
			eff.replaceStrings(lo.layer, "sources."+src.ID+".exclude", &src.Exclude, o.Exclude)
			setValue(eff, lo.layer, "sources."+src.ID+".max_file_bytes", &src.MaxFileBytes, o.MaxFileBytes)
			for id, on := range o.Enrichers {
				if _, known := src.Enrichers[id]; !known {
					// Config may toggle only an enricher the catalog attached, never attach one.
					return &RejectionError{lo.layer, "sources." + src.ID + ".enrichers." + id,
						"the compiled catalog does not attach that enricher to this source"}
				}
				if on && !lo.layer.IsLocal() {
					// An enricher reads a database the raw pipeline never touches, so only a local layer may enable one.
					continue
				}
				// The map still points into the compiled catalog; mutating without a clone edits it for the life of the process.
				if !clonedEnrichers {
					src.Enrichers = maps.Clone(src.Enrichers)
					clonedEnrichers = true
				}
				src.Enrichers[id] = on
				eff.setOrigin("sources."+src.ID+".enrichers."+id, lo.layer)
			}
		}

		// Recomputed from the effective read-affecting fields, so a changed glob resets exactly this source's state.
		src.SpecFingerprint = sources.SpecFingerprint(src.Source)
		eff.setDerived("sources." + src.ID + ".spec_fingerprint")
		eff.setDerived("sources." + src.ID + ".root")
		eff.setOrigin("sources."+src.ID+".artifact_class", LayerBundledCatalog)
	}
	return nil
}

func unionStrings(base, add []string) []string {
	out := slices.Clone(base)
	for _, a := range add {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func mergeExemptions(base, add map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range base {
		out[k] = slices.Clone(v)
	}
	for k, v := range add {
		out[k] = unionStrings(out[k], v)
	}
	return out
}

func setValue[T any](eff *Effective, layer Layer, field string, dst, value *T) {
	if value != nil {
		*dst = *value
		eff.setOrigin(field, layer)
	}
}

func (eff *Effective) mergeStrings(layer Layer, field string, dst *[]string, values []string) {
	if len(values) > 0 {
		*dst = unionStrings(*dst, values)
		eff.setOrigin(field, layer)
	}
}

func (eff *Effective) replaceStrings(layer Layer, field string, dst *[]string, values []string) {
	if len(values) > 0 {
		*dst = slices.Clone(values)
		eff.setOrigin(field, layer)
	}
}
