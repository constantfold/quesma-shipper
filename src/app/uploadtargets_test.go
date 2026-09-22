package app

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

func TestUploadTargetsBuildsTheAllowlist(t *testing.T) {
	eff := &config.Effective{UploadTargets: []config.UploadTarget{
		{Origin: "https://acme.s3.example.com", Addressing: "virtual-hosted"},
		{Origin: "http://127.0.0.1:9000", Addressing: "path-style", PathPrefix: "/acme", AllowLoopbackHTTP: true},
	}}
	list, err := uploadTargets(eff)
	require.NoErrorf(t, err, "uploadTargets: %v", err)
	require.Lenf(t, list, 2, "built %d targets, want 2", len(list))
	assert.Equal(t, "https://acme.s3.example.com:443", list[0].Origin())
	_, matchErr := list.Match("https://acme.s3.example.com/organization%3Dacme/object.age")
	assert.NoErrorf(t, matchErr, "allowlist does not match its own origin: %v", matchErr)
	_, unlistedErr := list.Match("https://elsewhere.example.com/object.age")
	assert.Error(t, unlistedErr, "an unlisted origin matched")
}

func TestUploadTargetsRefusesTheWholeListOnOneBadEntry(t *testing.T) {
	eff := &config.Effective{UploadTargets: []config.UploadTarget{
		{Origin: "https://acme.s3.example.com", Addressing: "virtual-hosted"},
		{Origin: "https://acme.s3.example.com", Addressing: "bucket-in-the-query"},
	}}
	list, err := uploadTargets(eff)
	require.Errorf(t, err, "bad addressing accepted: %+v", list)
	assert.Containsf(t, err.Error(), "entry 1", "refusal does not name the offending entry: %v", err)
	assert.Truef(t, list == nil, "a refused list still returned %d targets", len(list))
}

// The bridge is only correct if a ticket that survives it also survives validation, so this runs
// the real validator rather than comparing maps.
func TestToUploadTicketFeedsValidation(t *testing.T) {
	target, err := upload.NewUploadTarget(upload.TargetSpec{
		Origin:     "https://acme.s3.example.com",
		Addressing: upload.VirtualHosted,
	})
	require.NoErrorf(t, err, "target: %v", err)
	prepared := upload.PreparedUpload{
		ObjectID:   "01J0000000000000000000000A",
		Key:        "organization=acme/source=claude-code/object.age",
		Body:       []byte("sealed"),
		SourceHash: "sha256:abc",
		Metadata:   map[string]string{"manifest-version": "3", "artifact-class": "trajectory", "kind": "mirror"},
	}
	issued := controlplane.Ticket{
		TicketID:  "ticket-1",
		ObjectID:  prepared.ObjectID,
		Method:    "PUT",
		URL:       "https://acme.s3.example.com/organization%3Dacme/source%3Dclaude-code/object.age?X-Amz-Signature=deadbeef",
		ExpiresAt: time.Unix(1750000000, 0).UTC(),
		RequiredHeaders: controlplane.TicketHeaders{
			"x-amz-meta-source-hash":      prepared.SourceHash,
			"x-amz-meta-ticket-id":        "ticket-1",
			"x-amz-meta-manifest-version": "3",
			"x-amz-meta-artifact-class":   "trajectory",
			"x-amz-meta-kind":             "mirror",
			"x-amz-tagging":               "class=trajectory",
		},
		ContentLength:       int64(len(prepared.Body)),
		ContentLengthSigned: true,
	}

	ticket := toUploadTicket(issued)
	require.NoError(t, upload.ValidateTicket(upload.UploadTargetList{target}, prepared, ticket))
	if _, ok := ticket.RequiredHeaders["x-amz-meta-source-id"]; ok {
		t.Error("an unset optional header reached the map")
	}
	assert.Equal(t, "class=trajectory", ticket.RequiredHeaders["x-amz-tagging"])
	assert.Truef(t, ticket.ContentLengthSigned && ticket.ExpiresAt == issued.ExpiresAt, "bridge dropped a field: %+v", ticket)
}
