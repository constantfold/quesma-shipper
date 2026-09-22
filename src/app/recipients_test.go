package app

import (
	"fmt"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/config"
	"github.com/QuesmaOrg/quesma-shipper/internal/identity"
)

func TestRecipientsFor(t *testing.T) {
	unit, err := identity.Mint(t.TempDir())
	require.NoError(t, err)
	org, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	orgKey := org.Recipient().String()
	for _, tc := range []struct {
		name       string
		install    bool
		additional []string
		want       []string
	}{
		{"install then additional", true, []string{orgKey}, []string{unit.Recipient().String(), orgKey}},
		{"withheld install", false, []string{orgKey}, []string{orgKey}},
		{"empty set", false, nil, nil},
		{"invalid additional key", true, []string{"not-an-age-key"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := recipientsFor(&config.Effective{
				IncludeInstallRecipient: tc.install, AdditionalRecipients: tc.additional,
			}, unit)
			if tc.want == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var keys []string
			for _, recipient := range got {
				keys = append(keys, recipient.(fmt.Stringer).String())
			}
			assert.Equal(t, tc.want, keys)
		})
	}
}
