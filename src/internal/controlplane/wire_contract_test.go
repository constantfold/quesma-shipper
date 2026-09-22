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

func compileWireSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	raw, err := fs.ReadFile(protocol.FS, pathpkg.Join("schemas", name))
	require.NoErrorf(t, err, "read %s: %v", name, err)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoErrorf(t, err, "parse %s: %v", name, err)
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource(name, doc))
	s, err := c.Compile(name)
	require.NoErrorf(t, err, "compile %s: %v", name, err)
	return s
}

func TestWireSchemasComplete(t *testing.T) {
	entries, err := fs.Glob(protocol.FS, "schemas/*.schema.json")
	require.NoError(t, err)
	versioned, err := fs.Glob(protocol.FS, "schemas/*/*.schema.json")
	require.NoError(t, err)
	entries = append(entries, versioned...)
	var want []string
	for name := range wireTypes {
		want = append(want, "schemas/"+name)
		compileWireSchema(t, name)
	}
	assert.ElementsMatch(t, want, entries, "every embedded schema needs a corresponding wire type")
}

// Fixed protocol examples also used by authorization request tests.
const (
	fixtureInstallID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	fixtureDeviceKey = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	fixtureRecipient = "age1cpx4grz9j4fkn36cfurggwcg4l0da5fyqadl8fwagtcwy55gt44qlclfa5"
	fixtureKeyRoot   = "v1/organization=acme/install=" + fixtureInstallID

	fixtureWriterID     = "8403c1de-6940-4e35-a19b-5c91c45fc379"
	fixtureTicketID     = "b1bd1a73-f16d-4a51-aac6-29f1f48b0658"
	fixtureSourceHash   = "94f4d055cd323cbae40c74b5ed35df51b8fb4f362d7f43acb9b85cfbca5f2cb8"
	fixtureShippedHash  = "f70fd6b3501a3ff995e69e00ad1b1813ac296cf0768d30445549f8aefbd598b7"
	fixtureMirrorKey    = fixtureKeyRoot + "/mirror/source=claude-code-transcripts/f91631a3882c7956a9d2061b96ea38fd75bc77549b85cab26c7b2b63db21ed73.age"
	fixtureHeartbeatKey = fixtureKeyRoot + "/state/heartbeat.json.age"
)

// Populate every wire field so closed schemas catch extra fields and incorrect tags.
func TestStructsMatchSchemas(t *testing.T) {
	mirror := sampleAuthorizeRequest()
	mirror.Objects[0].Metadata.AgentVersion = "0.0.0-test"
	mirror.Objects[0].Metadata.ShapeSniff = "ok"
	mirror.Objects[0].Metadata.Derived = "true"
	mirror.Objects[0].Metadata.EnrichStatus = "ok"
	cases := []struct {
		name   string
		schema string
		v      any
	}{
		{"enroll request, invite", "enroll-request.schema.json", controlplane.EnrollRequest{
			Invite: "9f8d2c1a-opaque-invite-token", InstallID: fixtureInstallID,
			DevicePublicKey: fixtureDeviceKey, AgeRecipient: fixtureRecipient,
			Hostname: "dev-laptop", Platform: "darwin/arm64",
		}},
		{"enroll request, grant", "enroll-request.schema.json", controlplane.EnrollRequest{
			Grant: "tsg1.b3BhcXVlLWdyYW50LXBheWxvYWQ.c2lnbmF0dXJl", InstallID: fixtureInstallID,
			DevicePublicKey: fixtureDeviceKey, AgeRecipient: fixtureRecipient,
			Hostname: "managed-host", Platform: "linux/amd64",
		}},
		{"enroll response", "enroll-response.schema.json", controlplane.EnrollResponse{Organization: "acme"}},
		{"config request", "config-request.schema.json", controlplane.ConfigRequest{
			AgentVersion: "0.0.0-test", ConfigVersions: []int{1},
		}},
		{"config response", "config-response.schema.json", controlplane.ConfigResponse{
			Config:    []byte("config_version: 1\n"),
			ExpiresAt: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC),
		}},
		// The request's object is a oneOf, so "fully populated" is two instances rather than
		// one: every mirror metadata name, and the heartbeat's lone kind.
		{"v2 authorize request, mirror", "v2/uploads-authorize-request.schema.json", mirror},
		{"v2 authorize request, heartbeat", "v2/uploads-authorize-request.schema.json", controlplane.AuthorizeRequest{
			WriterID: fixtureWriterID,
			IssuedAt: time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
			Objects: []controlplane.UploadObject{{
				ObjectID: "heartbeat", Key: fixtureHeartbeatKey, Size: 8261,
				SourceHash: fixtureSourceHash,
				Metadata:   controlplane.UploadMetadata{Kind: "heartbeat"},
			}},
		}},
		{"v2 authorize response", "v2/uploads-authorize-response.schema.json", controlplane.AuthorizeResponse{
			Tickets: []controlplane.Ticket{{
				TicketID: fixtureTicketID, ObjectID: "trajectory-1", Method: "PUT",
				URL:       "https://archive.example.invalid/object?X-Amz-Signature=FIXTURE",
				ExpiresAt: time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC),
				RequiredHeaders: controlplane.TicketHeaders{
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
				},
				ContentLength: 481239, ContentLengthSigned: true,
			}},
		}},
		{"v2 authorize response, already present", "v2/uploads-authorize-response.schema.json", controlplane.AuthorizeResponse{
			Tickets: []controlplane.Ticket{{TicketID: fixtureTicketID, ObjectID: "trajectory-1", AlreadyPresent: true}},
		}},
		{"v2 authorize response, gcs", "v2/uploads-authorize-response.schema.json", controlplane.AuthorizeResponse{
			Tickets: []controlplane.Ticket{{
				TicketID: fixtureTicketID, ObjectID: "trajectory-1", Method: "PUT",
				URL:       "https://storage.googleapis.com/archive/object?X-Goog-Signature=FIXTURE",
				ExpiresAt: time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC),
				RequiredHeaders: controlplane.TicketHeaders{
					"x-goog-meta-source-hash": fixtureSourceHash,
					"x-goog-meta-ticket-id":   fixtureTicketID,
				},
				ContentLength: 481239, ContentLengthSigned: true,
			}},
		}},
		{"v2 authorize response, azure", "v2/uploads-authorize-response.schema.json", controlplane.AuthorizeResponse{
			Tickets: []controlplane.Ticket{{
				TicketID: fixtureTicketID, ObjectID: "trajectory-1", Method: "PUT",
				URL:       "https://archive.blob.core.windows.net/container/object?sig=FIXTURE",
				ExpiresAt: time.Date(2026, 8, 19, 12, 5, 0, 0, time.UTC),
				RequiredHeaders: controlplane.TicketHeaders{
					"x-ms-meta-source_hash": fixtureSourceHash,
					"x-ms-meta-ticket_id":   fixtureTicketID,
					"x-ms-blob-type":        "BlockBlob",
					"x-ms-tags":             "class=trajectory",
				},
				ContentLength: 481239, ContentLengthSigned: true,
			}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.v)
			require.NoError(t, err)
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
			require.NoError(t, err)
			assert.NoError(t, compileWireSchema(t, tc.schema).Validate(doc))
		})
	}
}

// fixtureSchema maps a fixture path to the schema that owns it. The auth directory is not
// a message and has no schema.
func fixtureSchema(path string) string {
	dir := pathpkg.Base(pathpkg.Dir(path))
	if dir == "auth" {
		return ""
	}
	kind := "response"
	if strings.Contains(pathpkg.Base(path), "request") {
		kind = "request"
	}
	switch dir {
	case "enroll":
		return "enroll-" + kind + ".schema.json"
	case "config":
		return "config-" + kind + ".schema.json"
	case "uploads-authorize":
		return "v2/uploads-authorize-" + kind + ".schema.json"
	}
	return ""
}

func wireFixtures(t *testing.T) []string {
	t.Helper()
	paths, err := fs.Glob(protocol.FS, "fixtures/*/*/*.json")
	require.Truef(t, err == nil && len(paths) != 0, "no embedded protocol fixtures (err: %v)", err)
	return paths
}

// Bad fixtures must fail validation; good fixtures must also survive strict typed round trips.
func TestWireFixtures(t *testing.T) {
	for _, path := range wireFixtures(t) {
		schema := fixtureSchema(path)
		if schema == "" {
			continue
		}
		t.Run(strings.TrimPrefix(path, "fixtures/"), func(t *testing.T) {
			raw, err := fs.ReadFile(protocol.FS, path)
			require.NoError(t, err)
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			require.NoError(t, err)
			err = compileWireSchema(t, schema).Validate(doc)
			bad := strings.HasPrefix(pathpkg.Base(path), "bad-")
			assert.Equalf(t, bad, err != nil, "%s validation: %v", schema, err)
			if bad {
				return
			}
			v := wireTypes[schema]()
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			require.NoError(t, dec.Decode(v))
			remarshaled, err := json.Marshal(v)
			require.NoError(t, err)
			assert.JSONEqf(t, string(raw), string(remarshaled), "round trip through %T changed the document", v)
		})
	}
}
