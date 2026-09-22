package engine_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// Files in a source overlap while the loop thread still owns every decision.

// peak records the most callers inside at once.
type peak struct {
	mu        sync.Mutex
	cur, most int
}

func (p *peak) enter() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cur++
	p.most = max(p.most, p.cur)
	return p.cur
}

func (p *peak) leave() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cur--
}

func (p *peak) max() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.most
}

// slowRecipient holds each seal open long enough for overlap to be observable in the compute leg.
type slowRecipient struct {
	inner age.Recipient
	peak
}

func (r *slowRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	r.enter()
	defer r.leave()
	time.Sleep(20 * time.Millisecond)
	return r.inner.Wrap(fileKey)
}

// slowPort holds the first group until a second arrives, so a network leg holding a compute slot times out.
type slowPort struct {
	*fakePort
	peak
	barrier chan struct{}
	once    sync.Once
}

func (p *slowPort) AuthorizeAndUpload(ctx context.Context, batch []engine.PreparedObject) []error {
	if p.enter() >= 2 {
		p.once.Do(func() { close(p.barrier) })
	} else {
		select {
		case <-p.barrier:
		case <-time.After(2 * time.Second):
		}
	}
	defer p.leave()
	return p.fakePort.AuthorizeAndUpload(ctx, batch)
}

// The one test that would notice the pool silently reduced to a sequential loop.
func TestFilesAreProcessedConcurrently(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/c%02d.jsonl", 8)
	slow := &slowRecipient{inner: f.unit.Recipient()}

	rep := f.run(func(o *engine.Options) {
		o.Workers = 4
		o.Recipients = []age.Recipient{slow}
	})

	require.Equalf(t, 8, rep.Shipped, "want 8 shipped, got %+v", rep)
	assert.Truef(t, slow.max() >= 2, "peak concurrent seals %d; the pass ran sequentially", slow.max())
}

// A sealed object leaves its compute slot before its group touches the network, so groups overlap.
func TestUploadsOverlapBeyondTheComputePool(t *testing.T) {
	f := newFixture(t)
	const files = 70
	f.writeTranscripts("p/u%02d.jsonl", files)
	f.plan.MaxFilesPerRun = files
	port := &slowPort{fakePort: f.port, barrier: make(chan struct{})}

	rep := f.run(func(o *engine.Options) {
		o.Workers = 2
		o.UploadWorkers = 64
		o.Upload = port
	})

	require.Equalf(t, files, rep.Shipped, "want %d shipped, got %+v", files, rep)
	assert.Truef(t, port.max() >= 2, "peak concurrent authorizations %d with 2 compute workers; groups are still holding compute slots", port.max())
}
