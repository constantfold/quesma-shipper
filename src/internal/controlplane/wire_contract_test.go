// Check local wire types against the independently versioned protocol schemas and fixtures.
package controlplane_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	pathpkg "path"
	"strings"
	"testing"
	"time"

	protocol "github.com/QuesmaOrg/shipper-protocol"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
)

// One type per protocol schema; completeness and fixture round trips share this mapping.
var wireTypes = map[string]func() any{
	"enroll-request.schema.json":                func() any { return &controlplane.EnrollRequest{} },
	"enroll-response.schema.json":               func() any { return &controlplane.EnrollResponse{} },
	"config-request.schema.json":                func() any { return &controlplane.ConfigRequest{} },
	"config-response.schema.json":               func() any { return &controlplane.ConfigResponse{} },
	"v2/uploads-authorize-request.schema.json":  func() any { return &controlplane.AuthorizeRequest{} },
	"v2/uploads-authorize-response.schema.json": func() any { return &controlplane.AuthorizeResponse{} },
}

// validateWire validates a JSON document against one embedded protocol schema.
func validateWire(t *testing.T, name string, raw []byte) error {
	t.Helper()
	schemaRaw, err := fs.ReadFile(protocol.FS, pathpkg.Join("schemas", name))
	require.NoError(t, err)
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource(name, schemaDoc))
	s, err := c.Compile(name)
	require.NoError(t, err, "compile %s", name)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	return s.Validate(doc)
}

func TestWireSchemasComplete(t *testing.T) {
	entries, err := fs.Glob(protocol.FS, "schemas/*.schema.json")
	require.NoError(t, err)
	versioned, err := fs.Glob(protocol.FS, "schemas/*/*.schema.json")
	require.NoError(t, err)
	var want []string
	for name := range wireTypes {
		want = append(want, "schemas/"+name)
	}
	assert.ElementsMatch(t, want, append(entries, versioned...), "every embedded schema needs a corresponding wire type")
}

// Fixed protocol examples also used by authorization request tests.
const (
	fixtureInstallID   = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	fixtureDeviceKey   = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	fixtureRecipient   = "age1cpx4grz9j4fkn36cfurggwcg4l0da5fyqadl8fwagtcwy55gt44qlclfa5"
	fixtureKeyRoot     = "v1/organization=acme/install=" + fixtureInstallID
	fixtureWriterID    = "8403c1de-6940-4e35-a19b-5c91c45fc379"
	fixtureTicketID    = "b1bd1a73-f16d-4a51-aac6-29f1f48b0658"
	fixtureSourceHash  = "94f4d055cd323cbae40c74b5ed35df51b8fb4f362d7f43acb9b85cfbca5f2cb8"
	fixtureShippedHash = "f70fd6b3501a3ff995e69e00ad1b1813ac296cf0768d30445549f8aefbd598b7"
	fixtureMirrorKey   = fixtureKeyRoot + "/mirror/source=claude-code-transcripts/f91631a3882c7956a9d2061b96ea38fd75bc77549b85cab26c7b2b63db21ed73.age"
)

func putTicket(url string, headers controlplane.TicketHeaders) controlplane.AuthorizeResponse {
	return controlplane.AuthorizeResponse{Tickets: []controlplane.Ticket{{
		TicketID: fixtureTicketID, ObjectID: "trajectory-1", Method: "PUT", URL: url,
		ExpiresAt: time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC), RequiredHeaders: headers,
		ContentLength: 481239, ContentLengthSigned: true,
	}}}
}

// Populate every wire field so closed schemas catch extra fields and incorrect tags.
func TestStructsMatchSchemas(t *testing.T) {
	mirror := sampleAuthorizeRequest()
	md := &mirror.Objects[0].Metadata
	md.AgentVersion, md.ShapeSniff, md.Derived, md.EnrichStatus = "0.0.0-test", "ok", "true", "ok"
	enroll := controlplane.EnrollRequest{InstallID: fixtureInstallID, DevicePublicKey: fixtureDeviceKey, AgeRecipient: fixtureRecipient}
	invite, grant := enroll, enroll
	invite.Invite, invite.Hostname, invite.Platform = "9f8d2c1a-opaque-invite-token", "dev-laptop", "darwin/arm64"
	grant.Grant, grant.Hostname, grant.Platform = "tsg1.b3BhcXVlLWdyYW50LXBheWxvYWQ.c2lnbmF0dXJl", "managed-host", "linux/amd64"
	const request, response = "v2/uploads-authorize-request.schema.json", "v2/uploads-authorize-response.schema.json"
	for _, tc := range []struct {
		name, schema string
		v            any
	}{
		{"enroll request, invite", "enroll-request.schema.json", invite},
		{"enroll request, grant", "enroll-request.schema.json", grant},
		{"enroll response", "enroll-response.schema.json", controlplane.EnrollResponse{Organization: "acme"}},
		{"config request", "config-request.schema.json", controlplane.ConfigRequest{AgentVersion: "0.0.0-test", ConfigVersions: []int{1}}},
		{"config response", "config-response.schema.json", controlplane.ConfigResponse{
			Config: []byte("config_version: 1\n"), ExpiresAt: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC),
		}},
		// The request's object is a oneOf: every mirror metadata name, and the heartbeat's lone kind.
		{"v2 authorize request, mirror", request, mirror},
		{"v2 authorize request, heartbeat", request, controlplane.AuthorizeRequest{
			WriterID: fixtureWriterID, IssuedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
			Objects: []controlplane.UploadObject{{
				ObjectID: "heartbeat", Key: fixtureKeyRoot + "/state/heartbeat.json.age", Size: 8261,
				SourceHash: fixtureSourceHash, Metadata: controlplane.UploadMetadata{Kind: "heartbeat"},
			}},
		}},
		{"v2 authorize response", response, putTicket("https://archive.example.invalid/object?X-Amz-Signature=FIXTURE", controlplane.TicketHeaders{
			"x-amz-meta-source-hash":      fixtureSourceHash,
			"x-amz-meta-ticket-id":        fixtureTicketID,
			"x-amz-meta-manifest-version": "1",
			"x-amz-meta-source-id":        "claude-code-transcripts",
			"x-amz-meta-shipped-hash":     fixtureShippedHash,
			"x-amz-meta-artifact-class":   "trajectory",
			"x-amz-meta-agent-version":    "0.0.0-test",
			"x-amz-meta-shape-sniff":      "ok",
			"x-amz-meta-derived":          "true",
			"x-amz-meta-enrich-status":    "ok",
			"x-amz-meta-kind":             "heartbeat",
			"x-amz-tagging":               "class=trajectory",
		})},
		{"v2 authorize response, already present", response, controlplane.AuthorizeResponse{
			Tickets: []controlplane.Ticket{{TicketID: fixtureTicketID, ObjectID: "trajectory-1", AlreadyPresent: true}},
		}},
		{"v2 authorize response, gcs", response, putTicket("https://storage.googleapis.com/archive/object?X-Goog-Signature=FIXTURE", controlplane.TicketHeaders{
			"x-goog-meta-source-hash": fixtureSourceHash, "x-goog-meta-ticket-id": fixtureTicketID,
		})},
		{"v2 authorize response, azure", response, putTicket("https://archive.blob.core.windows.net/container/object?sig=FIXTURE", controlplane.TicketHeaders{
			"x-ms-meta-source_hash": fixtureSourceHash, "x-ms-meta-ticket_id": fixtureTicketID,
			"x-ms-blob-type": "BlockBlob", "x-ms-tags": "class=trajectory",
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.v)
			require.NoError(t, err)
			assert.NoError(t, validateWire(t, tc.schema, payload))
		})
	}
}

// Bad fixtures fail validation; good ones also survive strict typed round trips. auth/ is not a message.
func TestWireFixtures(t *testing.T) {
	paths, err := fs.Glob(protocol.FS, "fixtures/*/*/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, paths, "no embedded protocol fixtures")
	for _, path := range paths {
		prefix := map[string]string{"enroll": "enroll-", "config": "config-", "uploads-authorize": "v2/uploads-authorize-"}[pathpkg.Base(pathpkg.Dir(path))]
		if prefix == "" {
			continue
		}
		schema := prefix + "response.schema.json"
		if strings.Contains(pathpkg.Base(path), "request") {
			schema = prefix + "request.schema.json"
		}
		t.Run(strings.TrimPrefix(path, "fixtures/"), func(t *testing.T) {
			raw, err := fs.ReadFile(protocol.FS, path)
			require.NoError(t, err)
			err = validateWire(t, schema, raw)
			bad := strings.HasPrefix(pathpkg.Base(path), "bad-")
			assert.Equal(t, bad, err != nil, "%s validation: %v", schema, err)
			if bad {
				return
			}
			v := wireTypes[schema]()
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			require.NoError(t, dec.Decode(v))
			remarshaled, err := json.Marshal(v)
			require.NoError(t, err)
			assert.JSONEq(t, string(raw), string(remarshaled), "round trip through %T changed the document", v)
		})
	}
}
