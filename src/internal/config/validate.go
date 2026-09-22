package config

import (
	"cmp"
	"net"
	"net/url"
	"slices"
	"strings"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/transforms/packs"
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

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// checkUploadTargets refuses an entry that could not pin a destination, so a typo fails at `config show`, not at the first upload.
func checkUploadTargets(eff *Effective) error {
	seen := map[string]bool{}
	for i, t := range eff.UploadTargets {
		reject := func(format string, args ...any) error {
			return eff.reject("upload_targets", "entry %d"+format, append([]any{i}, args...)...)
		}
		if t.Origin == "" {
			return reject(" names no origin")
		}
		u, err := url.Parse(t.Origin)
		switch {
		case err != nil, u.Host == "":
			return reject(": %q is not a scheme://host[:port] origin", t.Origin)
		case u.Opaque != "", u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
			return reject(": %q carries more than an origin: the bucket belongs in path_prefix", t.Origin)
		case u.User != nil:
			return reject(": %q carries user information", t.Origin)
		case strings.Contains(u.Hostname(), "*"):
			return reject(": %q is a wildcard host: a target is pinned or it is not a target", t.Origin)
		}
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && t.AllowLoopbackHTTP && isLoopback(u.Hostname()):
		case u.Scheme == "http" && t.AllowLoopbackHTTP:
			return reject(": %q is http but %q is not loopback", t.Origin, u.Hostname())
		case u.Scheme == "http":
			return reject(": %q is http without allow_loopback_http: a presigned URL is a bearer credential", t.Origin)
		default:
			return reject(": %q uses scheme %q, want https", t.Origin, u.Scheme)
		}
		switch t.Addressing {
		case "virtual-hosted":
			if t.PathPrefix != "" {
				return reject(": virtual-hosted addressing declares path_prefix %q, but the bucket is already the host", t.PathPrefix)
			}
		case "path-style":
			if !strings.HasPrefix(t.PathPrefix, "/") || t.PathPrefix == "/" || strings.HasSuffix(t.PathPrefix, "/") {
				return reject(": path-style addressing needs a /bucket path_prefix, got %q", t.PathPrefix)
			}
		default:
			return reject(": addressing %q is not one of [virtual-hosted path-style]", t.Addressing)
		}
		// One origin, one entry, with the port explicit so example and example:443 compare equal.
		port := cmp.Or(u.Port(), map[string]string{"http": "80", "https": "443"}[u.Scheme])
		key := strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
		if seen[key] {
			return reject(" repeats origin %q", t.Origin)
		}
		seen[key] = true
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
