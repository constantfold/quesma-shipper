package engine_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// --- the parallel pass ------------------------------------------------------
//
// Files in a source overlap; the loop thread still owns every decision. These tests pin what
// overlap must not change: the budget, the report's order, the fatal stop, and that it overlaps.

// out.Files is index-addressed, so the report reads in candidate order however work interleaved.
func TestTheReportKeepsCandidateOrderHoweverTheWorkFinished(t *testing.T) {
	f := newFixture(t)
	var want []string
	for i := 0; i < 12; i++ {
		rel := fmt.Sprintf("p/o%02d.jsonl", i)
		f.writeTranscript(rel, line1)
		want = append(want, "projects/"+rel)
	}

	rep := f.run(func(o *engine.Options) { o.Workers = 8 })

	files := rep.Sources[0].Files
	require.Lenf(t, files, len(want), "want %d files in the report, got %d", len(want), len(files))
	for i, fo := range files {
		assert.Equalf(t, want[i], fo.RelPath, "position %d: want %s, got %s", i, want[i], fo.RelPath)
	}
}

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

// slowPort holds the first authorization group until a second arrives: only a network leg folded
// back into a compute slot runs into the timeout.
type slowPort struct {
	*fakePort
	peak
	gate chan struct{}
	once sync.Once
}

func (p *slowPort) AuthorizeAndUpload(ctx context.Context, batch []engine.PreparedObject) []error {
	if p.enter() >= 2 {
		p.once.Do(func() { close(p.gate) })
	} else {
		select {
		case <-p.gate:
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

// Authorization groups are not bound by the compute pool: a sealed object leaves its compute slot
// before its group touches the network. The 70 files and the wide upload pool put two in flight.
func TestUploadsOverlapBeyondTheComputePool(t *testing.T) {
	f := newFixture(t)
	const files = 70
	f.writeTranscripts("p/u%02d.jsonl", files)
	f.plan.MaxFilesPerRun = files
	port := &slowPort{fakePort: f.port, gate: make(chan struct{})}

	rep := f.run(func(o *engine.Options) {
		o.Workers = 2
		o.UploadWorkers = 64
		o.Upload = port
	})

	require.Equalf(t, files, rep.Shipped, "want %d shipped, got %+v", files, rep)
	assert.Truef(t, port.max() >= 2, "peak concurrent authorizations %d with 2 compute workers; groups are still holding compute slots", port.max())
}
