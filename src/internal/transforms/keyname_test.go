package transforms

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The key-name rule is the only backstop for a credential with no recognisable shape. The
// dangerous half is the lookalikes: a rule firing on anything containing "token" would redact
// every usage figure in every transcript, and one firing on "id" or "key" would take session ids
// and object keys with it.
func TestFieldNamesThatOnlyLookLikeCredentials(t *testing.T) {
	m := newKeyNameMatcher(DefaultSecretKeyNames())
	for _, key := range []string{
		// All of these shipped in the clear.
		"api_key", "apiKey", "API_KEY", "x-api-key", "apikey",
		"password", "Password", "passwd", "pwd",
		"token", "Token", "authorization", "Authorization", "cookie",
		"secret", "private_key", "privateKey", "credentials", "auth",
		"aws.secret_access_key", "signing_key", "encryption_key",
		// These matched before and must keep matching.
		"access_token", "client_secret", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "MY_TOKEN",
	} {
		assert.Truef(t, m.MatchesKeyName(key), "%q names a secret", key)
	}
	for _, key := range []string{
		// Counts. Every token number the ETL reports arrives under one of these.
		"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
		"max_tokens", "total_tokens", "token_count", "tokenCount", "usage",
		// Identifiers, not credentials.
		"sessionId", "session_id", "install_id", "request_id", "uuid", "toolUseId",
		// Ordinary fields that end in a word the rule cares about only in context.
		"object_key", "cache_key", "keyRoot", "model", "content", "type",
		// A setting about secrets is not a secret.
		"secret_count", "secret_scanning_enabled",
	} {
		assert.Falsef(t, m.MatchesKeyName(key), "%q is not a credential and would be redacted", key)
	}
}

func TestKeyNamesSplitOnSeparatorsAndCamelHumps(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"api_key", []string{"api", "key"}},
		{"apiKey", []string{"api", "key"}},
		{"x-api-key", []string{"x", "api", "key"}},
		{"AWSSecretKey", []string{"aws", "secret", "key"}},
		{"aws.secret_access_key", []string{"aws", "secret", "access", "key"}},
		{"HTTPToken", []string{"http", "token"}},
		{"", nil},
	} {
		assert.Truef(t, slices.Equal(tc.want, splitKeyWords(tc.in)), "%q: want %v", tc.in, tc.want)
	}
}
