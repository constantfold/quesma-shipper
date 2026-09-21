package upload

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exact-key check is a byte comparison, so the encoder must produce the fixture's spelling.
func TestCanonicalPathReproducesGoldenTicketPath(t *testing.T) {
	prepared, ticket := goldenPair(t, "request.json", "response.json")

	parsed, err := url.Parse(ticket.URL)
	require.NoErrorf(t, err, "parse golden ticket url: %v", err)
	want := parsed.EscapedPath()
	require.Equal(t, "/"+canonicalPath(prepared.Key), want)

	// Why hand-rolled: net/url leaves "=" unescaped and every mirror key carries organization=.
	require.NotEqual(t, (&url.URL{Path: "/" + prepared.Key}).EscapedPath(), want)
}

func TestCanonicalPathEscaping(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"organization=acme", "organization%3Dacme"},
		{"a/b/c.age", "a/b/c.age"},
		{"keep-._~", "keep-._~"},
		{"space here", "space%20here"},
		{"plus+sign", "plus%2Bsign"},
		{"percent%41", "percent%2541"},
		{"colon:slash?query", "colon%3Aslash%3Fquery"},
		{"café", "caf%C3%A9"},
	}
	for _, c := range cases {
		assert.Equal(t, canonicalPath(c.key), c.want)
	}
}

func TestCanonicalPathUsesUppercaseHex(t *testing.T) {
	got := canonicalPath("=")
	require.Equalf(t, "%3D", got, "canonicalPath(\"=\") = %q, want %%3D", got)
	require.Truef(t, !strings.ContainsAny(got, "abcdef"), "canonicalPath produced lowercase hex: %q", got)
}

func TestValidateKeyRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"leading slash":  "/v1/object.age",
		"trailing slash": "v1/object.age/",
		"empty segment":  "v1//object.age",
		"dot segment":    "v1/./object.age",
		"dotdot segment": "v1/../object.age",
		"backslash":      `v1\object.age`,
		"control byte":   "v1/object\n.age",
		"too long":       strings.Repeat("a", maxKeyLength+1),
	}
	for name, key := range cases {
		assert.Error(t, validateKey(key), name)
	}
	require.NoError(t, validateKey("v1/organization=acme/mirror/object.age"))
}
