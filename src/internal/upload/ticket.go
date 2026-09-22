// Local ticket validation: nothing in an authorization response may validate anything else in
// it. Every field is checked against the prepared object or the machine owner's allowlist.
package upload

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// A provider's header names. The set is closed: a name outside it invalidates the whole ticket.
type headerDialect struct {
	metadataPrefix, tagging string
	azure                   bool // metadata names use _ for -, and x-ms-blob-type is required
}

var headerDialects = []headerDialect{{"x-amz-meta-", "x-amz-tagging", false}, {"x-goog-meta-", "", false}, {"x-ms-meta-", "x-ms-tags", true}}

func (d headerDialect) metadata(name string) string {
	if d.azure {
		name = strings.ReplaceAll(name, "-", "_")
	}
	return d.metadataPrefix + name
}

// MetadataNames is the declarable metadata allowlist, a copy of controlplane's kept equal by a test in app.
var MetadataNames = []string{
	"manifest-version", "source-id", "shipped-hash", "artifact-class",
	"agent-version", "shape-sniff", "derived", "enrich-status", "kind",
}

// taggingValues is the closed tag set: any other value means the ticket is not from this protocol.
var taggingValues = []string{"class=trajectory", "class=context"}

// maxKeyLength is the object-store key ceiling; a longer key is an upstream bug, never truncated.
const maxKeyLength = 1024

// PreparedUpload is the sealed object this machine holds: the trusted side of every comparison.
type PreparedUpload struct {
	ObjectID   string
	Key        string
	Body       []byte
	SourceHash string            // the manifest's pre-redaction source digest, not a checksum of Body
	Metadata   map[string]string // unprefixed names from MetadataNames
}

// Ticket mirrors the issued PUT capability, declared here so this package imports no plane client.
type Ticket struct {
	TicketID            string
	ObjectID            string
	Method              string
	URL                 string
	ExpiresAt           time.Time // for the caller's reauthorization decision; the store decides actual expiry
	RequiredHeaders     map[string]string
	ContentLength       int64
	ContentLengthSigned bool // the provider signature confines the exact body size
}

// ValidateTicket refuses anything but this exact object at a configured target; errors never quote the URL.
func ValidateTicket(targets UploadTargetList, prepared PreparedUpload, ticket Ticket) error {
	target, u, err := targets.match(ticket.URL)
	id := prepared.ObjectID
	switch {
	case err != nil:
		return err
	case id == "":
		return errors.New("upload: prepared object carries no object id")
	case ticket.ObjectID != id:
		return fmt.Errorf("upload: ticket names object %q, prepared object is %q", ticket.ObjectID, id)
	case ticket.Method != "PUT":
		return fmt.Errorf("upload: ticket for object %q authorizes method %q", id, ticket.Method)
	case ticket.ContentLength != int64(len(prepared.Body)):
		return fmt.Errorf("upload: ticket for object %q authorizes %d bytes, prepared object is %d", id, ticket.ContentLength, len(prepared.Body))
	case !ticket.ContentLengthSigned:
		return fmt.Errorf("upload: ticket for object %q does not sign its content length", id)
	}
	if err := validatePath(target, prepared, u.EscapedPath()); err != nil {
		return err
	}
	return validateHeaders(prepared, ticket)
}

// validatePath is the exact-key check: the right origin still permits another install's key.
func validatePath(target UploadTarget, prepared PreparedUpload, escaped string) error {
	id := prepared.ObjectID
	if err := validateKey(prepared.Key); err != nil {
		return fmt.Errorf("upload: prepared object %q: %w", id, err)
	}
	// Named refusals first: the byte comparison catches these too, but says only "not the key".
	segments := strings.Split(escaped, "/")
	lower := strings.ToLower(escaped)
	switch {
	case strings.Contains(escaped, "//"):
		return fmt.Errorf("upload: ticket path for object %q has an empty segment", id)
	case slices.Contains(segments, "."), slices.Contains(segments, ".."):
		return fmt.Errorf("upload: ticket path for object %q has a dot segment", id)
	case strings.Contains(lower, "%2f"):
		return fmt.Errorf("upload: ticket path for object %q encodes a slash", id)
	case strings.Contains(lower, "%5c"):
		return fmt.Errorf("upload: ticket path for object %q encodes a backslash", id)
	}

	// Compared as bytes, never normalized first: normalizing turns a hostile path plausible.
	want := target.pathPrefix + "/" + canonicalPath(prepared.Key)
	switch target.addressing {
	case VirtualHosted, PathStyle:
		if escaped == want {
			return nil
		}
	case addressingUnpinned:
		// No declared layout, so accept the key at the root or below exactly one bucket segment.
		if bucket, ok := strings.CutSuffix(escaped, want); ok && strings.Count(bucket, "/") <= 1 {
			return nil
		}
	default:
		return fmt.Errorf("upload: target %s declares unknown addressing %q", target.Origin(), string(target.addressing))
	}
	return fmt.Errorf("upload: ticket path does not name the prepared key for object %q", id)
}

// validateHeaders enforces the closed header set; a header the server invented is a refusal.
func validateHeaders(prepared PreparedUpload, ticket Ticket) error {
	h, id := ticket.RequiredHeaders, prepared.ObjectID
	dialect, err := ticketHeaderDialect(h)
	sourceHash, ticketID := dialect.metadata("source-hash"), dialect.metadata("ticket-id")
	switch {
	case err != nil:
		return fmt.Errorf("upload: ticket for object %q: %w", id, err)
	case prepared.SourceHash == "":
		return fmt.Errorf("upload: prepared object %q carries no source hash", id)
	case ticket.TicketID == "":
		return fmt.Errorf("upload: ticket for object %q carries no ticket id", id)
	case h[sourceHash] != prepared.SourceHash:
		return fmt.Errorf("upload: ticket for object %q requires source hash %q, prepared object hashed %q", id, h[sourceHash], prepared.SourceHash)
	}
	switch got, ok := h[ticketID]; {
	case !ok:
		return fmt.Errorf("upload: ticket for object %q requires no %s header", id, ticketID)
	case got != ticket.TicketID:
		return fmt.Errorf("upload: ticket %q for object %q requires ticket-id header %q", ticket.TicketID, id, got)
	}

	for name, want := range prepared.Metadata {
		if !slices.Contains(MetadataNames, name) {
			return fmt.Errorf("upload: prepared object %q declares metadata %q outside the closed set", id, name)
		}
		header := dialect.metadata(name)
		switch got, ok := h[header]; {
		case !ok:
			return fmt.Errorf("upload: ticket for object %q requires no %s header, which the prepared object declared", id, header)
		case got != want:
			return fmt.Errorf("upload: ticket for object %q requires %s=%q, prepared object declared %q", id, header, got, want)
		}
	}
	if dialect.azure && h["x-ms-blob-type"] != "BlockBlob" {
		return fmt.Errorf("upload: ticket for object %q does not require x-ms-blob-type=BlockBlob", id)
	}

	for name, got := range h {
		metadata, isMetadata := strings.CutPrefix(name, dialect.metadataPrefix)
		if dialect.azure {
			metadata = strings.ReplaceAll(metadata, "_", "-")
		}
		switch {
		case got == "":
			return fmt.Errorf("upload: ticket for object %q requires header %q with an empty value", id, name)
		case name == sourceHash, name == ticketID, dialect.azure && name == "x-ms-blob-type":
		case name == dialect.tagging && dialect.tagging != "":
			if !slices.Contains(taggingValues, got) {
				return fmt.Errorf("upload: ticket for object %q requires tag %q", id, got)
			}
		case isMetadata && slices.Contains(MetadataNames, metadata):
			// Present here but absent above: the server derived it from nothing we sent.
			if prepared.Metadata[metadata] != got {
				return fmt.Errorf("upload: ticket for object %q requires %s=%q, which the prepared object did not declare", id, name, got)
			}
		default:
			return fmt.Errorf("upload: ticket for object %q requires header %q outside the closed provider set", id, name)
		}
	}
	return nil
}

// ticketHeaderDialect picks the provider by its source-hash header; exactly one must be present.
func ticketHeaderDialect(headers map[string]string) (headerDialect, error) {
	var found []headerDialect
	for _, d := range headerDialects {
		if _, ok := headers[d.metadata("source-hash")]; ok {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return headerDialect{}, errors.New("carries no recognized source-hash header")
	case 1:
		return found[0], nil
	}
	return headerDialect{}, errors.New("mixes provider header dialects")
}

func validateKey(key string) error {
	switch {
	case key == "":
		return errors.New("key is empty")
	case len(key) > maxKeyLength:
		return fmt.Errorf("key is %d bytes, over the %d ceiling", len(key), maxKeyLength)
	case strings.HasPrefix(key, "/"), strings.HasSuffix(key, "/"):
		return errors.New("key starts or ends with a slash")
	case strings.Contains(key, `\`):
		return errors.New("key contains a backslash")
	}
	if i := strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
		return fmt.Errorf("key contains a control byte at offset %d", i)
	}
	return validateSegments(key)
}

func validateSegments(path string) error {
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "":
			return errors.New("has an empty segment")
		case ".", "..":
			return errors.New("has a dot segment")
		}
	}
	return nil
}

// Query escaping supplies uppercase percent-hex; paths keep slashes and spell spaces as %20.
func canonicalPath(key string) string {
	escaped := strings.ReplaceAll(url.QueryEscape(key), "+", "%20")
	return strings.ReplaceAll(escaped, "%2F", "/")
}
