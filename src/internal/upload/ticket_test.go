package upload

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTicketAcceptsGolden(t *testing.T) {
	for _, pair := range [][2]string{{"request.json", "response.json"}, {"request-heartbeat.json", "response-heartbeat.json"}} {
		prepared, ticket := goldenPair(t, pair[0], pair[1])
		require.NoError(t, ValidateTicket(UploadTargetList{goldenTarget(t)}, prepared, ticket), pair[0])
	}
}

// The golden AWS headers respelled for each other provider must validate too.
func TestValidateTicketAcceptsEveryProviderDialect(t *testing.T) {
	prepared, base := goldenPair(t, "request.json", "response.json")
	for name, respell := range map[string]func(header string) string{
		"gcs": func(h string) string {
			if h == "x-amz-tagging" {
				return "" // gcs has no tagging header
			}
			return strings.Replace(h, "x-amz-meta-", "x-goog-meta-", 1)
		},
		"azure": func(h string) string {
			if h == "x-amz-tagging" {
				return "x-ms-tags"
			}
			return "x-ms-meta-" + strings.ReplaceAll(strings.TrimPrefix(h, "x-amz-meta-"), "-", "_")
		},
	} {
		ticket := base
		ticket.RequiredHeaders = map[string]string{}
		for h, value := range base.RequiredHeaders {
			if respelled := respell(h); respelled != "" {
				ticket.RequiredHeaders[respelled] = value
			}
		}
		if name == "azure" {
			ticket.RequiredHeaders["x-ms-blob-type"] = "BlockBlob"
		}
		require.NoError(t, ValidateTicket(UploadTargetList{goldenTarget(t)}, prepared, ticket), name)
	}
}

func TestValidateTicketRejectsURL(t *testing.T) {
	prepared, ticket := goldenPair(t, "request.json", "response.json")
	targets := UploadTargetList{goldenTarget(t)}
	replace := func(old, new string) string { return strings.Replace(ticket.URL, old, new, 1) }
	cases := []struct {
		name, url string
		wantErr   error
	}{
		{"unlisted origin", replace("archive.example.invalid", "evil.example.invalid"), ErrNoTarget},
		{"unlisted port", replace("archive.example.invalid", "archive.example.invalid:8443"), ErrNoTarget},
		{"sibling install key", replace("3f2504e0-4f89-41d3-9a0c-0305e82c3301", "11111111-2222-3333-4444-555555555555"), nil},
		{"key suffix confusion", replace(".age?", ".age.evil?"), nil},
		{"unescaped separator", strings.ReplaceAll(ticket.URL, "%3D", "="), nil},
		{"lowercase escape", strings.ReplaceAll(ticket.URL, "%3D", "%3d"), nil},
		{"duplicate slash", replace("/mirror/", "//mirror/"), nil},
		{"dot segment", replace("/mirror/", "/mirror/./"), nil},
		{"parent segment", replace("/mirror/", "/mirror/../"), nil},
		{"encoded slash", replace("/mirror/", "%2Fmirror/"), nil},
		{"encoded backslash", replace("/mirror/", "/mirror%5C"), nil},
		{"user information", replace("https://", "https://user:pass@"), nil},
		{"fragment", ticket.URL + "#frag", nil},
		{"opaque url", "https:archive.example.invalid", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ticket.URL = tc.url
			err := ValidateTicket(targets, prepared, ticket)
			require.Error(t, err)
			require.Truef(t, tc.wantErr == nil || errors.Is(err, tc.wantErr), "error is %v, want %v", err, tc.wantErr)
			assertNoURLLeak(t, err, ticket.URL)
		})
	}
}

func TestValidateTicketRejects(t *testing.T) {
	base, baseTicket := goldenPair(t, "request.json", "response.json")
	targets := UploadTargetList{goldenTarget(t)}
	type mutation func(*PreparedUpload, *Ticket)
	set := func(name, value string) mutation {
		return func(_ *PreparedUpload, tk *Ticket) { tk.RequiredHeaders[name] = value }
	}
	drop := func(name string) mutation {
		return func(_ *PreparedUpload, tk *Ticket) { delete(tk.RequiredHeaders, name) }
	}

	for _, c := range []struct {
		name   string
		mutate mutation
	}{
		{"object id mismatch", func(_ *PreparedUpload, tk *Ticket) { tk.ObjectID = "trajectory-2" }},
		{"method is not PUT", func(_ *PreparedUpload, tk *Ticket) { tk.Method = "POST" }},
		{"content length mismatch", func(_ *PreparedUpload, tk *Ticket) { tk.ContentLength++ }},
		{"content length unsigned", func(_ *PreparedUpload, tk *Ticket) { tk.ContentLengthSigned = false }},
		{"prepared key not canonical", func(p *PreparedUpload, tk *Ticket) {
			p.Key = "/" + p.Key
			tk.URL = "https://archive.example.invalid/" + canonicalPath(p.Key) + "?X-Amz-Signature=FIXTURE"
		}},
		{"unknown provider header", set("x-amz-acl", "public-read")},
		{"unknown metadata header", set("x-amz-meta-operator", "someone")},
		{"missing source hash header", drop("x-amz-meta-source-hash")},
		{"missing ticket id header", drop("x-amz-meta-ticket-id")},
		{"source hash disagrees with the prepared object", set("x-amz-meta-source-hash", strings.Repeat("a", 64))},
		{"ticket id header disagrees with the ticket", set("x-amz-meta-ticket-id", "00000000-0000-0000-0000-000000000000")},
		{"metadata value disagrees", set("x-amz-meta-source-id", "another-source")},
		{"metadata the prepared object never declared", set("x-amz-meta-agent-version", "9.9.9")},
		{"metadata dropped from the ticket", drop("x-amz-meta-source-id")},
		{"tag outside the closed set", set("x-amz-tagging", "class=anything")},
		{"empty tag value", set("x-amz-tagging", "")},
		{"emptied metadata value", set("x-amz-meta-artifact-class", "")},
		{"mixed provider dialects", set("x-goog-meta-source-hash", base.SourceHash)},
		{"prepared metadata outside the closed set", func(p *PreparedUpload, tk *Ticket) {
			p.Metadata["operator"] = "someone"
			tk.RequiredHeaders["x-amz-meta-operator"] = "someone"
		}},
		{"prepared object carries no source hash", func(p *PreparedUpload, _ *Ticket) { p.SourceHash = "" }},
		{"prepared object carries no object id", func(p *PreparedUpload, tk *Ticket) { p.ObjectID, tk.ObjectID = "", "" }},
		{"ticket carries no ticket id", func(_ *PreparedUpload, tk *Ticket) { tk.TicketID = "" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			prepared, ticket := base, baseTicket
			prepared.Metadata = maps.Clone(base.Metadata)
			ticket.RequiredHeaders = maps.Clone(baseTicket.RequiredHeaders)
			c.mutate(&prepared, &ticket)
			err := ValidateTicket(targets, prepared, ticket)
			require.Error(t, err)
			assertNoURLLeak(t, err, ticket.URL)
		})
	}
}

// Without a pinned target, either root-level keys or one bucket segment are allowed.
func TestValidateTicketAddressing(t *testing.T) {
	const origin = "https://minio.example.invalid:9000"
	target, err := NewUploadTarget(TargetSpec{
		Origin: origin, Addressing: PathStyle, PathPrefix: "/trajectories",
	})
	require.NoError(t, err)
	prepared, ticket := goldenPair(t, "request.json", "response.json")
	key := canonicalPath(prepared.Key)
	for _, tc := range []struct {
		name, url        string
		pinned, unpinned bool
	}{
		{"virtual hosted", ticket.URL, false, true},
		{"path style", origin + "/trajectories/" + key + "?X-Amz-Signature=FIXTURE", true, true},
		{"bucket prefix missing", origin + "/" + key, false, true},
		{"neighbouring bucket", origin + "/trajectories-staging/" + key, false, true},
		{"prefix without boundary", origin + "/trajectoriesx/" + key, false, true},
		{"prefix repeated", origin + "/trajectories/trajectories/" + key, false, false},
		{"two bucket segments", origin + "/a/b/" + key, false, false},
		{"empty bucket segment", origin + "//" + key, false, false},
		{"sibling install key", origin + "/trajectories/" + canonicalPath(strings.Replace(prepared.Key,
			"3f2504e0-4f89-41d3-9a0c-0305e82c3301", "11111111-2222-3333-4444-555555555555", 1)), false, false},
		{"key suffix confusion", origin + "/" + key + ".evil", false, false},
	} {
		ticket.URL = tc.url
		for _, mode := range []struct {
			targets UploadTargetList
			accept  bool
		}{{UploadTargetList{target}, tc.pinned}, {UploadTargetList{}, tc.unpinned}} {
			err := ValidateTicket(mode.targets, prepared, ticket)
			if mode.accept {
				require.NoError(t, err, "%s, %d pinned targets", tc.name, len(mode.targets))
			} else {
				require.Error(t, err, "%s, %d pinned targets", tc.name, len(mode.targets))
				assertNoURLLeak(t, err, ticket.URL)
			}
		}
	}
}

// An addressing form nobody taught the validator is a refusal, never a pass-through.
func TestValidateTicketUnknownAddressing(t *testing.T) {
	prepared, ticket := goldenPair(t, "request.json", "response.json")
	target := goldenTarget(t)
	target.addressing = Addressing("dns-style")
	require.Error(t, ValidateTicket(UploadTargetList{target}, prepared, ticket), "unknown addressing was accepted")
}

// The exact-key check is a byte comparison, so the encoder must produce the store's spelling:
// path escaping would leave "=" literal, while the signed key spelling requires %3D.
func TestCanonicalPathEscaping(t *testing.T) {
	for key, want := range map[string]string{
		"=":                 "%3D",
		"organization=acme": "organization%3Dacme",
		"%2F+ /":            "%252F%2B%20/",
		"a/b/c.age":         "a/b/c.age",
		"keep-._~":          "keep-._~",
		"space here":        "space%20here",
		"plus+sign":         "plus%2Bsign",
		"percent%41":        "percent%2541",
		"colon:slash?query": "colon%3Aslash%3Fquery",
		"café":              "caf%C3%A9",
	} {
		assert.Equal(t, want, canonicalPath(key), key)
	}
}

func TestValidateKeyRejects(t *testing.T) {
	for name, key := range map[string]string{
		"empty":          "",
		"leading slash":  "/v1/object.age",
		"trailing slash": "v1/object.age/",
		"empty segment":  "v1//object.age",
		"dot segment":    "v1/./object.age",
		"dotdot segment": "v1/../object.age",
		"backslash":      `v1\object.age`,
		"control byte":   "v1/object\n.age",
		"too long":       strings.Repeat("a", maxKeyLength+1),
	} {
		assert.Error(t, validateKey(key), name)
	}
	require.NoError(t, validateKey("v1/organization=acme/mirror/object.age"))
}
