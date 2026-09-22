// Package upload sends one prepared object through one presigned PUT ticket. The bytes go to a
// URL the control plane issued, so local validation is the only defence against a URL naming
// another install's key. A ticket URL is a credential: no log line, span or error may carry one.
package upload

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Addressing is the URL layout a target uses; an unknown form is refused rather than guessed at.
type Addressing string

const (
	VirtualHosted Addressing = "virtual-hosted" // the bucket is the host; the path is "/" plus the key
	PathStyle     Addressing = "path-style"     // the path is the pinned "/bucket" prefix plus the key

	// addressingUnpinned marks a target adopted from a ticket's own origin when nothing was pinned,
	// so the exact-key check accepts either layout.
	addressingUnpinned Addressing = "unpinned"
)

// ErrNoTarget names the origin and never the path or query: the origin is not the secret part.
var ErrNoTarget = errors.New("upload: ticket origin is not an allowed upload target")

// TargetSpec is the machine owner's declaration of one upload target: local configuration or
// enrollment only, never an authorization response or served configuration.
type TargetSpec struct {
	Origin            string // scheme://host[:port] and nothing else
	Addressing        Addressing
	PathPrefix        string // empty for virtual-hosted, "/bucket" for path-style, compared literally
	AllowLoopbackHTTP bool   // admits http:// for a loopback host; development only
}

// UploadTarget is one validated origin plus its addressing; the zero value matches nothing.
type UploadTarget struct {
	origin     string // scheme://host:port, port always explicit so :443 and the default form compare equal
	addressing Addressing
	pathPrefix string
}

// UploadTargetList is the machine owner's optional origin pin; empty means unpinned (see Match).
type UploadTargetList []UploadTarget

// NewUploadTarget validates one machine-owner declaration.
func NewUploadTarget(spec TargetSpec) (UploadTarget, error) {
	fail := func(format string, args ...any) (UploadTarget, error) {
		return UploadTarget{}, fmt.Errorf("upload: target origin %q "+format, append([]any{spec.Origin}, args...)...)
	}
	u, err := url.Parse(strings.TrimSpace(spec.Origin))
	switch {
	case err != nil:
		return fail("does not parse")
	case u.Opaque != "":
		return fail("is opaque")
	case u.Host == "":
		return fail("names no host")
	case u.User != nil:
		return fail("carries user information")
	case u.Fragment != "":
		return fail("carries a fragment")
	case u.RawQuery != "":
		return fail("carries a query")
	case u.Path != "" && u.Path != "/":
		return fail("carries a path: put the bucket in PathPrefix")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	switch scheme := strings.ToLower(u.Scheme); {
	case strings.Contains(host, "*"):
		return fail("is a wildcard host")
	case scheme == "https":
	case scheme == "http" && !spec.AllowLoopbackHTTP:
		return fail("is http and loopback development mode is off")
	case scheme == "http" && host != "localhost" && (ip == nil || !ip.IsLoopback()):
		return fail("is http but %q is not loopback", host)
	case scheme != "http":
		return fail("uses scheme %q", u.Scheme)
	}
	prefix, err := validatePathPrefix(spec.Addressing, spec.PathPrefix)
	if err != nil {
		return UploadTarget{}, err
	}
	return UploadTarget{origin: originOf(u), addressing: spec.Addressing, pathPrefix: prefix}, nil
}

// Origin is the pinned scheme://host:port, with the port always explicit.
func (t UploadTarget) Origin() string { return t.origin }

// Match returns the entry a ticket URL belongs to. An empty list is unpinned: the ticket's own
// origin becomes the target, but every other check still applies, so an owner trusts the plane
// on WHERE, never on WHAT.
func (l UploadTargetList) Match(rawURL string) (UploadTarget, error) {
	t, _, err := l.match(rawURL)
	return t, err
}

// match is Match keeping the parsed URL, so validation never parses a ticket twice.
func (l UploadTargetList) match(rawURL string) (UploadTarget, *url.URL, error) {
	u, err := parseTicketURL(rawURL)
	if err != nil {
		return UploadTarget{}, nil, err
	}
	if len(l) == 0 {
		// https only: with no pinned entry there is no opt-in to read, and a presigned URL in cleartext is exposed on the wire.
		if u.Scheme != "https" {
			return UploadTarget{}, nil, errors.New("upload: ticket url is http and no upload targets are configured: " +
				"only a configured upload_targets entry may admit a non-https origin")
		}
		return UploadTarget{origin: originOf(u), addressing: addressingUnpinned}, u, nil
	}
	for _, t := range l {
		if t.origin == originOf(u) {
			return t, u, nil
		}
	}
	return UploadTarget{}, nil, fmt.Errorf("%w: %s", ErrNoTarget, originOf(u))
}

// parseTicketURL is the single door a ticket URL enters through; its errors quote nothing.
func parseTicketURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, errors.New("upload: ticket url does not parse")
	case u.Opaque != "":
		return nil, errors.New("upload: ticket url is opaque")
	case u.Host == "":
		return nil, errors.New("upload: ticket url names no host")
	case u.User != nil:
		return nil, errors.New("upload: ticket url carries user information")
	case u.Fragment != "", u.RawFragment != "":
		return nil, errors.New("upload: ticket url carries a fragment")
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("upload: ticket url uses scheme %q", u.Scheme)
	}
	return u, nil
}

func originOf(u *url.URL) string {
	port := u.Port()
	switch {
	case port != "":
	case strings.EqualFold(u.Scheme, "http"):
		port = "80"
	default:
		port = "443"
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// validatePathPrefix keeps the bucket where the addressing says; escapes would make the exact-key
// comparison ambiguous, so a prefix must be literal.
func validatePathPrefix(addressing Addressing, prefix string) (string, error) {
	switch addressing {
	case VirtualHosted:
		if prefix != "" {
			return "", fmt.Errorf("upload: virtual-hosted target declares path prefix %q: the bucket is already the host", prefix)
		}
		return "", nil
	case PathStyle:
		body := strings.TrimPrefix(prefix, "/")
		switch {
		case !strings.HasPrefix(prefix, "/") || prefix == "/":
			return "", fmt.Errorf("upload: path-style target needs a /bucket path prefix, got %q", prefix)
		case strings.HasSuffix(prefix, "/"):
			return "", fmt.Errorf("upload: path prefix %q ends in a slash", prefix)
		case validateSegments(body) != nil:
			return "", fmt.Errorf("upload: path prefix %q: %w", prefix, validateSegments(body))
		case canonicalPath(body) != body:
			return "", fmt.Errorf("upload: path prefix %q is not literal", prefix)
		}
		return prefix, nil
	default:
		return "", fmt.Errorf("upload: unknown addressing form %q", string(addressing))
	}
}
