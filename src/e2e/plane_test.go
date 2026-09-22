package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Spelled out rather than imported, so a change to the client's constant is noticed.
const vendPreamble = "trajectory-shipper-upload-authorize-v2\nPOST\n/v2/uploads/authorize\n"

type authorizeRequest struct {
	WriterID string `json:"writer_id"`
	Objects  []struct {
		ObjectID   string            `json:"object_id"`
		Key        string            `json:"key"`
		Size       int64             `json:"size"`
		SourceHash string            `json:"source_hash"`
		Metadata   map[string]string `json:"metadata"`
	} `json:"objects"`
}

// fakePlane checks the device signature before reading any object field, as the real service is specified.
type fakePlane struct {
	server *httptest.Server
	store  *fakeStore
	pub    ed25519.PublicKey

	mu           sync.Mutex
	status       int             // what the next authorize answers; 200 issues tickets
	ttl          time.Duration   // how long an issued ticket lives
	staleBatches int             // how many of the next authorizations issue already-expired tickets
	misdirect    string          // the install id every ticket URL is re-signed to name, for the exact-key check
	issued       int             // authorizations answered, so every minted ticket id is distinct
	batches      [][]string      // the keys of each authorize call, in call order
	present      []string        // every key answered already_present instead of ticketed
	writers      map[string]bool // every distinct writer_id seen
	faults       []string        // protocol invariants the client broke
}

func startFakePlane(t *testing.T, store *fakeStore, pub ed25519.PublicKey) *fakePlane {
	t.Helper()
	p := &fakePlane{store: store, pub: pub, status: http.StatusOK, ttl: 10 * time.Minute, writers: map[string]bool{}}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakePlane) set(change func(p *fakePlane)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

func (p *fakePlane) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v2/uploads/authorize" {
		// Including the config fetch: the run continues on the layers it already has.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.verify(r.Header.Get("Authorization"), body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	p.mu.Lock()
	status, ttl := p.status, p.ttl
	stale := p.staleBatches > 0
	if stale {
		p.staleBatches--
		ttl = -time.Second
	}
	seq := p.issued
	p.issued++
	p.mu.Unlock()
	if status != http.StatusOK {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "30")
		}
		http.Error(w, fmt.Sprintf("the control plane was told to answer %d", status), status)
		return
	}

	var req authorizeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "undecodable request: "+err.Error(), http.StatusBadRequest)
		return
	}

	tickets := make([]map[string]any, 0, len(req.Objects))
	keys := make([]string, 0, len(req.Objects))
	var present []string
	expires := time.Now().Add(ttl).UTC()
	for i, obj := range req.Objects {
		p.check(obj.ObjectID, obj.Key, obj.Size, obj.SourceHash, obj.Metadata)
		keys = append(keys, obj.Key)
		ticketID := fmt.Sprintf("ticket-%d-%d", seq, i)
		// Bytes already stored under this source hash are answered for, and the client sends nothing.
		if hash, held := p.store.sourceHash(obj.Key); held && hash == obj.SourceHash {
			present = append(present, obj.Key)
			tickets = append(tickets, map[string]any{
				"ticket_id": ticketID, "object_id": obj.ObjectID, "already_present": true,
			})
			continue
		}
		// The server-derived tag: the client cannot request one, so it comes from the key's container.
		tagging := "class=context"
		if strings.Contains(obj.Key, "/mirror/") {
			tagging = "class=trajectory"
		}
		headers := map[string]string{
			"x-amz-meta-source-hash": obj.SourceHash,
			"x-amz-meta-ticket-id":   ticketID,
			"x-amz-tagging":          tagging,
		}
		for name, value := range obj.Metadata {
			headers["x-amz-meta-"+name] = value
		}
		tickets = append(tickets, map[string]any{
			"ticket_id":             ticketID,
			"object_id":             obj.ObjectID,
			"method":                "PUT",
			"url":                   p.ticketURL(obj.Key, stale),
			"expires_at":            expires.Format(time.RFC3339Nano),
			"required_headers":      headers,
			"content_length":        obj.Size,
			"content_length_signed": true,
		})
	}

	p.mu.Lock()
	p.batches = append(p.batches, keys)
	p.present = append(p.present, present...)
	p.writers[req.WriterID] = true
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"tickets": tickets})
}

func (p *fakePlane) verify(header string, body []byte) error {
	_, rest, ok := strings.Cut(header, "sig=")
	if !strings.HasPrefix(header, "Shipper-Device org=default, install=") || !ok {
		return fmt.Errorf("authorization header is not a device signature: %q", header)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return fmt.Errorf("device signature is not base64: %w", err)
	}
	if !ed25519.Verify(p.pub, append([]byte(vendPreamble), body...), sig) {
		return fmt.Errorf("device signature does not cover the preamble and this body")
	}
	return nil
}

// Faults are reported at the end of the test, naming the object; a 400 would read as a generic failure.
func (p *fakePlane) check(objectID, key string, size int64, sourceHash string, md map[string]string) {
	fault := func(format string, args ...any) {
		p.mu.Lock()
		p.faults = append(p.faults, fmt.Sprintf(format, args...))
		p.mu.Unlock()
	}
	if objectID == "" {
		fault("object under key %s carries no object_id", key)
	}
	if size <= 0 {
		fault("object %q declares size %d", objectID, size)
	}
	if len(sourceHash) != 64 || strings.ToLower(sourceHash) != sourceHash {
		fault("object %q declares source_hash %q, want 64 lowercase hex", objectID, sourceHash)
	}
	for _, banned := range []string{"source-hash", "ticket-id"} {
		if _, present := md[banned]; present {
			fault("object %q requested server-derived metadata %q", objectID, banned)
		}
	}
	if !strings.Contains(key, "install="+testInstallID) {
		fault("object %q names key %q, outside this install's root", objectID, key)
	}
}

func (p *fakePlane) ticketURL(key string, stale bool) string {
	if p.misdirect != "" {
		key = strings.Replace(key, testInstallID, p.misdirect, 1)
	}
	url := p.store.server.URL + "/" + vendBucket + "/" + canonicalKeyPath(key) + "?sig=" + p.store.sign(key)
	if stale {
		url += "&expired=1"
	}
	return url
}

func (p *fakePlane) authorizeBatches() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.batches)
}

func (p *fakePlane) answeredPresent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.present)
}

func (p *fakePlane) assertClean(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.faults {
		t.Errorf("authorization request broke a protocol invariant: %s", f)
	}
}

// The writer id is minted once per process, so a run presenting two reports itself as two machines.
func (p *fakePlane) assertOneWriter(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	assert.Lenf(t, p.writers, 1, "one run presented %d writer ids, want exactly one", len(p.writers))
}
