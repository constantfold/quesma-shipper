package config_test

import (
	"slices"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
)

func testRecipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id.Recipient().String()
}

func TestPolicyGradeLayersAddRecipientsAsAUnion(t *testing.T) {
	home := fakeHome(t)
	userRec, orgRec := testRecipient(t), testRecipient(t)

	eff := resolved(t, home, layerDoc(t, config.LayerUser, "encryption:\n  additional_recipients: ["+userRec+"]\n"), layerDoc(t, config.LayerRemote, "encryption:\n  additional_recipients: ["+orgRec+", "+userRec+"]\n"))
	want := []string{userRec, orgRec}
	assert.Truef(t, slices.Equal(eff.AdditionalRecipients, want), "additional recipients:\n got %v\nwant %v (union, first-seen order, no duplicates)", eff.AdditionalRecipients, want)
}

// Rejecting at resolve time is what makes the refresh path fall back to the last valid config.
func TestUnparseableRecipientIsRejectedAtResolveTime(t *testing.T) {
	home := fakeHome(t)
	body := "encryption:\n  additional_recipients: [not-an-age-key]\n"
	for _, layer := range []config.Layer{config.LayerUser, config.LayerRemote} {
		_, err := config.Resolve(baseInput(t, home,
			layerDoc(t, layer, body),
		))
		require.Errorf(t, err, "a recipient that does not parse must be a resolve-time rejection (%v layer)", layer)
	}
}

// The served remote config is the org's recipient channel.
func TestServedRemoteConfigAddsRecipients(t *testing.T) {
	home := fakeHome(t)
	rec := testRecipient(t)

	eff := resolved(t, home, layerDoc(t, config.LayerRemote, "org: acme\nencryption:\n  additional_recipients: ["+rec+"]\n"))
	assert.Truef(t, slices.Equal(eff.AdditionalRecipients, []string{rec}), "served recipients did not land: %v", eff.AdditionalRecipients)
	assert.True(t, eff.IncludeInstallRecipient, "a served config that does not mention include_install_recipient must not withhold it")
	origin := eff.Provenance["encryption.additional_recipients"]
	assert.Equalf(t, config.LayerRemote, origin.Layer, "provenance should be the remote layer, got %v", origin.Layer)
}

// An org may withhold the install's own key, but only while at least one additional recipient exists.
func TestWithholdingTheInstallRecipientRequiresAnotherReader(t *testing.T) {
	home := fakeHome(t)

	_, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerRemote, `
encryption:
  include_install_recipient: false
`),
	))
	require.Error(t, err, "withholding the only recipient must be rejected: it would seal objects no key can open")

	rec := testRecipient(t)
	eff, err := config.Resolve(baseInput(t, home,
		layerDoc(t, config.LayerRemote, "encryption:\n  include_install_recipient: false\n  additional_recipients: ["+rec+"]\n"),
	))
	require.NoErrorf(t, err, "withhold plus an org reader is the documented enterprise shape: %v", err)
	assert.True(t, !eff.IncludeInstallRecipient, "include_install_recipient=false from the served layer did not take effect")
	assert.Truef(t, slices.Equal(eff.AdditionalRecipients, []string{rec}), "additional recipients: %v", eff.AdditionalRecipients)
}
