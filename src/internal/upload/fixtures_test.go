package upload

import (
	"encoding/json"
	"io/fs"
	"path"
	"testing"
	"time"

	protocol "github.com/QuesmaOrg/shipper-protocol"
	"github.com/stretchr/testify/require"
)

// The golden authorization pair from the shipper-protocol v2 fixtures anchors every validation test: key
// grammar, escaped path and header set come from what the control plane is tested against.

// goldenPair loads one fixture request and response into this package's types, as app/ does.
func goldenPair(t *testing.T, requestFixture, responseFixture string) (PreparedUpload, Ticket) {
	t.Helper()
	var request struct {
		Objects []struct {
			ObjectID   string            `json:"object_id"`
			Key        string            `json:"key"`
			Size       int64             `json:"size"`
			SourceHash string            `json:"source_hash"`
			Metadata   map[string]string `json:"metadata"`
		} `json:"objects"`
	}
	var response struct {
		Tickets []struct {
			TicketID            string            `json:"ticket_id"`
			ObjectID            string            `json:"object_id"`
			Method              string            `json:"method"`
			URL                 string            `json:"url"`
			ExpiresAt           time.Time         `json:"expires_at"`
			RequiredHeaders     map[string]string `json:"required_headers"`
			ContentLength       int64             `json:"content_length"`
			ContentLengthSigned bool              `json:"content_length_signed"`
		} `json:"tickets"`
	}
	for name, into := range map[string]any{requestFixture: &request, responseFixture: &response} {
		raw, err := fs.ReadFile(protocol.FS, path.Join("fixtures", "v2", "uploads-authorize", name))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, into))
	}
	require.Len(t, request.Objects, 1)
	require.Len(t, response.Tickets, 1)
	o := request.Objects[0]
	return PreparedUpload{ObjectID: o.ObjectID, Key: o.Key, Body: make([]byte, o.Size), SourceHash: o.SourceHash, Metadata: o.Metadata},
		Ticket(response.Tickets[0])
}

// goldenTarget is the machine-owner allowlist entry the fixture URLs belong to.
func goldenTarget(t *testing.T) UploadTarget {
	t.Helper()
	target, err := NewUploadTarget(TargetSpec{Origin: "https://archive.example.invalid", Addressing: VirtualHosted})
	require.NoErrorf(t, err, "build golden target: %v", err)
	return target
}
