package sources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeychainMissingService(t *testing.T) {
	raw, err := readAccountKeychain(context.Background(), "quesma-shipper-test-missing-credential-914ebc04")
	require.Truef(t, len(raw) == 0 && err != nil && err.Error() == "Keychain unavailable", "Keychain query: bytes=%d err=%v", len(raw), err)
}
