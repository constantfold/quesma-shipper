package config

import (
	"slices"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

func checkConfigVersion(eff *Effective) error {
	if eff.ConfigVersion == 0 {
		eff.ConfigVersion = AcceptedConfigVersions[0]
		eff.setOrigin("config_version", LayerCompiledDefaults)
		return nil
	}
	if !slices.Contains(AcceptedConfigVersions, eff.ConfigVersion) {
		return eff.reject("config_version", "%d is not an accepted config_version %v", eff.ConfigVersion, AcceptedConfigVersions)
	}
	return nil
}

// checkUploadTargets refuses an entry that could not pin a destination, so a typo fails at `config show`, not at the first upload.
func checkUploadTargets(eff *Effective) error {
	seen := map[string]bool{}
	for i, t := range eff.UploadTargets {
		target, err := upload.NewUploadTarget(upload.TargetSpec{Origin: t.Origin, Addressing: upload.Addressing(t.Addressing),
			PathPrefix: t.PathPrefix, AllowLoopbackHTTP: t.AllowLoopbackHTTP})
		switch {
		case err != nil:
			return eff.reject("upload_targets", "entry %d: %v", i, err)
		case seen[target.Origin()]:
			return eff.reject("upload_targets", "entry %d repeats origin %q", i, t.Origin)
		}
		seen[target.Origin()] = true
	}
	return nil
}

// checkRulePacks refuses an unknown pack once here rather than at transforms.New per file per tick.
func checkRulePacks(eff *Effective) error {
	available := packs.Available()
	for _, name := range eff.RulePacks {
		if !slices.Contains(available, name) {
			return eff.reject("scrub.rule_packs", "%q is not a rule pack this build has %v", name, available)
		}
	}
	return nil
}

// checkEncryption validates recipients at resolve time, where a bad config falls back; at seal time it would abort every flush.
func checkEncryption(eff *Effective) error {
	for _, r := range eff.AdditionalRecipients {
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return eff.reject("encryption.additional_recipients", "%q is not an age X25519 recipient: %v", r, err)
		}
	}
	if !eff.IncludeInstallRecipient && len(eff.AdditionalRecipients) == 0 {
		return eff.reject("encryption.include_install_recipient",
			"withholding the install recipient with no additional_recipients would seal objects no key can open")
	}
	return nil
}
