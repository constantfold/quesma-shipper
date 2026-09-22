package formats

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// NameKeySize is the per-install secret's length in bytes, sized for HMAC-SHA256.
const NameKeySize = 32

// UserPlaceholder is for convergence, not concealment: a file keeps its key when the home path changes.
const UserPlaceholder = "__USER__"

// identifierRe is the grammar for organization, install and source ids: a "/" or "=" in a key segment could forge a path.
var identifierRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// CanonicalPath is the same on every run and machine, so a re-ship after state loss overwrites, never duplicates.
func CanonicalPath(sourceRelPath, username string) string {
	p := strings.TrimPrefix(path.Clean(strings.ReplaceAll(sourceRelPath, `\`, "/")), "/")
	if p == "." {
		p = ""
	}
	p = ApplyUserPlaceholder(p, username)
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = encodeSegment(s)
	}
	return strings.Join(segs, "/")
}

// ApplyUserPlaceholder replaces username only between non-alphanumerics, so "janes-notes.md" survives; short names are ignored.
func ApplyUserPlaceholder(s, username string) string {
	if len(username) < 2 || s == "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], username) {
			end := i + len(username)
			if (i == 0 || !isAlnum(s[i-1])) && (end == len(s) || !isAlnum(s[end])) {
				b.WriteString(UserPlaceholder)
				i = end
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// encodeSegment percent-encodes everything outside [A-Za-z0-9._~-], "%" included, so the encoding is injective.
func encodeSegment(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// MirrorName is keyed, since a plain path hash in a listable key is an oracle, and path-derived, so history shares one key.
func MirrorName(nameKey []byte, canonicalPath string) string {
	m := hmac.New(sha256.New, nameKey)
	// The domain tag keeps a later name kind from colliding with mirror keys.
	m.Write([]byte("mirror:" + canonicalPath))
	return hex.EncodeToString(m.Sum(nil))
}

// MirrorKey is identity-first so erasure is one prefix delete; standalone installs pass "default" as the org.
func MirrorKey(org, installID, sourceID string, nameKey []byte, canonicalPath string) (string, error) {
	root, err := InstallRoot(org, installID)
	if err != nil {
		return "", err
	}
	if err := checkSegment("source", sourceID); err != nil {
		return "", err
	}
	if len(nameKey) != NameKeySize {
		return "", fmt.Errorf("identity: name_key is %d bytes, want %d", len(nameKey), NameKeySize)
	}
	return fmt.Sprintf("%s/mirror/source=%s/%s.age", root, sourceID, MirrorName(nameKey, canonicalPath)), nil
}

// StateKey sits under the install prefix, so one sweep erases it with everything else.
func StateKey(org, installID, name string) (string, error) {
	root, err := InstallRoot(org, installID)
	if err != nil {
		return "", err
	}
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("identity: state object name %q must be non-empty and contain no slash", name)
	}
	return root + "/state/" + name, nil
}

func checkSegment(kind, v string) error {
	if !identifierRe.MatchString(v) {
		return fmt.Errorf("identity: %s segment %q is not a legal key segment", kind, v)
	}
	return nil
}

// UsernameFromPath reads /Users/<name> or /home/<name>; shared so engine and doctor cannot disagree.
func UsernameFromPath(p string) string {
	segments := strings.Split(strings.ReplaceAll(p, `\`, "/"), "/")
	for i, seg := range segments {
		if (seg == "Users" || seg == "home") && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return ""
}

// InstallRoot shares MirrorKey's segments, so the server-side key scope cannot drift from the keys written.
func InstallRoot(org, installID string) (string, error) {
	if err := checkSegment("organization", org); err != nil {
		return "", err
	}
	if err := checkSegment("install", installID); err != nil {
		return "", err
	}
	return fmt.Sprintf("v1/organization=%s/install=%s", org, installID), nil
}
