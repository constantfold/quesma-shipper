package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Path-style, the addressing a self-hosted store uses and the one whose exact-key check has a
// prefix to get wrong.
const vendBucket = "trajectories"

// One accepted upload: the key, the provider headers that arrived with it, and the exact bytes.
type storedPut struct {
	Key     string
	Headers map[string]string
	Body    []byte
}

// fakeStore accepts presigned PUTs, signed with a shared HMAC over the key rather than SigV4: an
// HMAC the client cannot compute proves the issued URL reached the store unaltered. It versions
// like a real deployment must: every PUT is kept and the newest write under a key is what is read.
type fakeStore struct {
	server *httptest.Server
	secret []byte

	mu   sync.Mutex
	puts []storedPut
}

func startFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	s := &fakeStore{secret: []byte("e2e-object-store-secret")}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

func (s *fakeStore) sign(key string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *fakeStore) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "the object store accepts PUT only, got "+r.Method, http.StatusMethodNotAllowed)
		return
	}
	prefix := "/" + vendBucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "path names no bucket", http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	if !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(s.sign(key))) {
		http.Error(w, "signature does not cover this key", http.StatusForbidden)
		return
	}

	// A store refuses an expired capability, whatever the bytes behind it are.
	if r.URL.Query().Get("expired") == "1" {
		http.Error(w, "Request has expired", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "short body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(body)) != r.ContentLength {
		http.Error(w, fmt.Sprintf("body is %d bytes, Content-Length declared %d",
			len(body), r.ContentLength), http.StatusBadRequest)
		return
	}
	headers := map[string]string{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = values[0]
		}
	}
	s.mu.Lock()
	s.puts = append(s.puts, storedPut{Key: key, Headers: headers, Body: body})
	s.mu.Unlock()

	w.Header().Set("ETag", `"`+s.sign(key)[:16]+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) stored() []storedPut {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.puts)
}

func (s *fakeStore) storedWhere(keep func(key string) bool) []storedPut {
	return slices.DeleteFunc(s.stored(), func(p storedPut) bool { return !keep(p.Key) })
}

// mirrorPuts are the trajectory objects, dropping the heartbeat every run writes.
func (s *fakeStore) mirrorPuts() []storedPut {
	return s.storedWhere(func(key string) bool { return strings.Contains(key, "/mirror/") })
}

func (s *fakeStore) heartbeats() []storedPut {
	return s.storedWhere(func(key string) bool { return strings.HasSuffix(key, heartbeatKey) })
}

// The write count under one key, which is the only thing making "the same file shipped twice"
// observable: the newest version alone cannot tell the two cases apart.
func (s *fakeStore) versions(key string) int {
	return len(s.storedWhere(func(k string) bool { return k == key }))
}

// The source hash the newest version under a key was stored with: what a real plane's HEAD reads
// back, and the only thing that tells "already holds these bytes" from "holds older ones".
func (s *fakeStore) sourceHash(key string) (string, bool) {
	puts := s.storedWhere(func(k string) bool { return k == key })
	if len(puts) == 0 {
		return "", false
	}
	return puts[len(puts)-1].Headers["x-amz-meta-source-hash"], true
}

// The server's escaped spelling of an object key, written out rather than imported: the exact-key
// check is only meaningful when the two sides derive it independently.
func canonicalKeyPath(key string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}
