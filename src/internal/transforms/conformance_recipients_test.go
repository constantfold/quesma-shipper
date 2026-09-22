package transforms

import (
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const recipientsVectorPath = "../../conformance/v1/seal/recipients.json"

// recipientsVector is the multi-recipient contract; age is nondeterministic, so it is asserted behaviorally.
type recipientsVector struct {
	VectorSet                 string `json:"vector_set"`
	VectorVersion             int    `json:"vector_version"`
	Description               string `json:"description"`
	Scheme                    string `json:"scheme"`
	KeyIDSource               string `json:"key_id_source"`
	KeyIDOrder                string `json:"key_id_order"`
	MinRecipients             int    `json:"min_recipients"`
	AnySingleIdentitySuffices bool   `json:"any_single_identity_suffices"`
}

func TestConformanceRecipients(t *testing.T) {
	var v recipientsVector
	readVectors(t, recipientsVectorPath, &v)

	install, org, escrow := identity(t), identity(t), identity(t)
	recipients := []age.Recipient{install.Recipient(), org.Recipient(), escrow.Recipient()}
	payload := []byte("{\"type\":\"user\"}\n")

	obj, _, err := Seal(manifest(), payload, recipients)
	require.NoError(t, err)

	// key_id_order: the manifest records the set in seal argument order.
	m, _, err := Open(obj, install)
	require.NoError(t, err)
	require.Equal(t, "age", v.Scheme)
	require.NotNil(t, m.Encryption)
	require.Equal(t, v.Scheme, m.Encryption.Scheme)
	wantIDs := []string{install.Recipient().String(), org.Recipient().String(), escrow.Recipient().String()}
	assert.Equal(t, wantIDs, m.Encryption.RecipientKeyIDs, "recipient_key_ids in seal argument order")

	// any_single_identity_suffices: the org reader and the escrow key each open the object alone.
	require.True(t, v.AnySingleIdentitySuffices, "the vector must claim any-single-identity: age's envelope construction guarantees it")
	for name, id := range map[string]*age.X25519Identity{"org": org, "escrow": escrow} {
		_, got, err := Open(obj, id)
		if assert.NoError(t, err, "the %s identity alone must open the object", name) {
			assert.Equal(t, string(payload), string(got), "the %s identity read a different payload", name)
		}
	}

	// And an identity outside the set must not.
	_, _, err = Open(obj, identity(t))
	assert.Error(t, err, "an identity that is not a recipient opened the object")

	// min_recipients: encryption is not optional, so zero recipients is a refusal.
	require.Equal(t, 1, v.MinRecipients, "min_recipients drifted")
	_, _, err = Seal(manifest(), payload, nil)
	assert.Error(t, err, "sealing to no recipients must be refused")
}
