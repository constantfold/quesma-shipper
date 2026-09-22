package upload

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKey = "v1/organization=acme/install=3f2504e0-4f89-41d3-9a0c-0305e82c3301/mirror/source=claude-code-transcripts/f91631a3882c7956a9d2061b96ea38fd75bc77549b85cab26c7b2b63db21ed73.age"

// objectStore records what actually arrived: the only way to check which headers were sent.
func objectStore(t *testing.T, respond http.HandlerFunc) (*httptest.Server, func() []*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var seen []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	return server, func() []*http.Request { mu.Lock(); defer mu.Unlock(); return seen }
}

func testTicket(origin string) (PreparedUpload, Ticket) {
	prepared := PreparedUpload{
		ObjectID: "trajectory-1", Key: testKey, Body: []byte("sealed-object-bytes"), SourceHash: strings.Repeat("a", 64),
		Metadata: map[string]string{"manifest-version": "1", "source-id": "claude-code-transcripts", "artifact-class": "trajectory"},
	}
	return prepared, Ticket{
		TicketID: "b1bd1a73-f16d-4a51-aac6-29f1f48b0658",
		ObjectID: "trajectory-1",
		Method:   "PUT",
		URL:      origin + "/" + canonicalPath(testKey) + "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
		RequiredHeaders: map[string]string{
			sourceHashHeader:              prepared.SourceHash,
			ticketIDHeader:                "b1bd1a73-f16d-4a51-aac6-29f1f48b0658",
			"x-amz-meta-manifest-version": "1",
			"x-amz-meta-source-id":        "claude-code-transcripts",
			"x-amz-meta-artifact-class":   "trajectory",
			taggingHeader:                 "class=trajectory",
		},
		ContentLength:       int64(len(prepared.Body)),
		ContentLengthSigned: true,
	}
}

func TestUploadSendsExactlyTheAuthorizedRequest(t *testing.T) {
	server, seen := objectStore(t, func(w http.ResponseWriter, _ *http.Request) {})
	prepared, ticket := testTicket(server.URL)
	target, err := NewUploadTarget(TargetSpec{Origin: server.URL, Addressing: VirtualHosted, AllowLoopbackHTTP: true})
	require.NoError(t, err)
	require.NoError(t, ValidateTicket(UploadTargetList{target}, prepared, ticket))

	require.NoError(t, New().Upload(context.Background(), ticket, prepared.Body))
	require.Len(t, seen(), 1)
	got := seen()[0]
	body, _ := io.ReadAll(got.Body)
	assert.Equal(t, http.MethodPut, got.Method)
	assert.Equal(t, "/"+canonicalPath(testKey), got.URL.EscapedPath())
	assert.Equal(t, string(prepared.Body), string(body))
	assert.Equal(t, ticket.ContentLength, got.ContentLength)
	for name, want := range ticket.RequiredHeaders {
		assert.Equal(t, want, got.Header.Get(name))
	}
	for name := range got.Header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-amz-") {
			assert.Contains(t, ticket.RequiredHeaders, lower, "object store saw an unauthorized provider header")
		}
	}
}

func TestUploadRefusesRedirect(t *testing.T) {
	server, seen := objectStore(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "moved") {
			w.Header().Set("Location", "/moved")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}
	})
	_, ticket := testTicket(server.URL)
	err := New().Upload(context.Background(), ticket, []byte("sealed-object-bytes"))
	require.ErrorIs(t, err, ErrRedirect)
	require.Len(t, seen(), 1, "want exactly the one request that was redirected")
	assertNoURLLeak(t, err, ticket.URL)
}

func TestUploadNonOKStatusIsAFailure(t *testing.T) {
	server, _ := objectStore(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<Error><Code>AccessDenied</Code>\n<Message>expired\ttoken</Message></Error>", http.StatusForbidden)
	})
	_, ticket := testTicket(server.URL)
	err := New().Upload(context.Background(), ticket, []byte("sealed-object-bytes"))
	var status *StatusError
	require.ErrorAs(t, err, &status)
	require.Equal(t, http.StatusForbidden, status.Status)
	require.NotContains(t, status.Reason, "\n", "reason was not sanitized")
	require.NotContains(t, status.Reason, "\t", "reason was not sanitized")
	require.Contains(t, status.Reason, "AccessDenied", "reason lost the store's diagnostic")
	assertNoURLLeak(t, err, ticket.URL)
}
