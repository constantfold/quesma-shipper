package upload

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateTicketAcceptsGolden(t *testing.T) {
	for _, pair := range []struct{ request, response string }{
		{"request.json", "response.json"},
		{"request-heartbeat.json", "response-heartbeat.json"},
	} {
		t.Run(pair.request, func(t *testing.T) {
			prepared, ticket := goldenPair(t, pair.request, pair.response)
			require.NoError(t, ValidateTicket(UploadTargetList{goldenTarget(t)}, prepared, ticket))
		})
	}
}

func TestValidateTicketAcceptsEveryProviderDialect(t *testing.T) {
	prepared, base := goldenPair(t, "request.json", "response.json")
	for _, tc := range []struct {
		name      string
		mapHeader func(string) (string, bool)
		extra     map[string]string
	}{
		{name: "aws", mapHeader: func(name string) (string, bool) { return name, true }},
		{name: "gcs", mapHeader: func(name string) (string, bool) {
			if name == taggingHeader {
				return "", false
			}
			return strings.Replace(name, metadataPrefix, "x-goog-meta-", 1), true
		}},
		{name: "azure", mapHeader: func(name string) (string, bool) {
			if name == taggingHeader {
				return "x-ms-tags", true
			}
			name = strings.TrimPrefix(name, metadataPrefix)
			return "x-ms-meta-" + strings.ReplaceAll(name, "-", "_"), true
		}, extra: map[string]string{"x-ms-blob-type": "BlockBlob"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ticket := base
			ticket.RequiredHeaders = make(map[string]string, len(base.RequiredHeaders)+len(tc.extra))
			for name, value := range base.RequiredHeaders {
				if mapped, ok := tc.mapHeader(name); ok {
					ticket.RequiredHeaders[mapped] = value
				}
			}
			maps.Copy(ticket.RequiredHeaders, tc.extra)
			require.NoError(t, ValidateTicket(UploadTargetList{goldenTarget(t)}, prepared, ticket))
		})
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
	pathOf := func(key string) string {
		return "https://archive.example.invalid/" + canonicalPath(key) + "?X-Amz-Signature=FIXTURE"
	}

	cases := []struct {
		name   string
		mutate func(prepared *PreparedUpload, ticket *Ticket)
	}{
		{"object id mismatch", func(_ *PreparedUpload, tk *Ticket) { tk.ObjectID = "trajectory-2" }},
		{"method is not PUT", func(_ *PreparedUpload, tk *Ticket) { tk.Method = "POST" }},
		{"content length mismatch", func(_ *PreparedUpload, tk *Ticket) { tk.ContentLength++ }},
		{"prepared key not canonical", func(p *PreparedUpload, tk *Ticket) {
			p.Key = "/" + p.Key
			tk.URL = pathOf(p.Key)
		}},
		{"unknown provider header", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders["x-amz-acl"] = "public-read"
		}},
		{"unknown metadata header", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders["x-amz-meta-operator"] = "someone"
		}},
		{"missing source hash header", func(_ *PreparedUpload, tk *Ticket) {
			delete(tk.RequiredHeaders, sourceHashHeader)
		}},
		{"missing ticket id header", func(_ *PreparedUpload, tk *Ticket) {
			delete(tk.RequiredHeaders, ticketIDHeader)
		}},
		{"source hash disagrees with the prepared object", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders[sourceHashHeader] = strings.Repeat("a", 64)
		}},
		{"ticket id header disagrees with the ticket", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders[ticketIDHeader] = "00000000-0000-0000-0000-000000000000"
		}},
		{"metadata value disagrees", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders["x-amz-meta-source-id"] = "another-source"
		}},
		{"metadata the prepared object never declared", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders["x-amz-meta-agent-version"] = "9.9.9"
		}},
		{"metadata dropped from the ticket", func(_ *PreparedUpload, tk *Ticket) {
			delete(tk.RequiredHeaders, "x-amz-meta-source-id")
		}},
		{"tag outside the closed set", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders[taggingHeader] = "class=anything"
		}},
		{"empty tag value", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders[taggingHeader] = ""
		}},
		{"emptied metadata value", func(_ *PreparedUpload, tk *Ticket) {
			tk.RequiredHeaders["x-amz-meta-artifact-class"] = ""
		}},
		{"prepared metadata outside the closed set", func(p *PreparedUpload, tk *Ticket) {
			p.Metadata["operator"] = "someone"
			tk.RequiredHeaders["x-amz-meta-operator"] = "someone"
		}},
		{"prepared object carries no source hash", func(p *PreparedUpload, _ *Ticket) { p.SourceHash = "" }},
		{"ticket carries no ticket id", func(_ *PreparedUpload, tk *Ticket) { tk.TicketID = "" }},
	}

	for _, c := range cases {
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
		t.Run(tc.name, func(t *testing.T) {
			ticket.URL = tc.url
			for _, mode := range []struct {
				name    string
				targets UploadTargetList
				accept  bool
			}{
				{"pinned", UploadTargetList{target}, tc.pinned},
				{"unpinned", UploadTargetList{}, tc.unpinned},
			} {
				t.Run(mode.name, func(t *testing.T) {
					err := ValidateTicket(mode.targets, prepared, ticket)
					if mode.accept {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						assertNoURLLeak(t, err, ticket.URL)
					}
				})
			}
		})
	}
}

// An addressing form nobody taught the validator is a refusal, never a pass-through.
func TestValidateTicketUnknownAddressing(t *testing.T) {
	prepared, ticket := goldenPair(t, "request.json", "response.json")
	target := goldenTarget(t)
	target.addressing = Addressing("dns-style")
	require.Error(t, ValidateTicket(UploadTargetList{target}, prepared, ticket), "unknown addressing was accepted")
}
