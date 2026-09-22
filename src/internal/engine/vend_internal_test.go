package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The authorization accumulator, exercised directly: the byte bound needs objects too large to
// produce through the loop, and overshooting it loses a whole group.

// sizePort records the ciphertext each group carried and stores everything.
type sizePort struct {
	mu     sync.Mutex
	groups [][]int
}

func (p *sizePort) AuthorizeAndUpload(_ context.Context, batch []PreparedObject) []error {
	sizes := make([]int, len(batch))
	for i, o := range batch {
		sizes[i] = len(o.Body)
	}
	p.mu.Lock()
	p.groups = append(p.groups, sizes)
	p.mu.Unlock()
	return make([]error, len(batch))
}

// stagedFor is one sealed object of a given size.
func stagedFor(idx, size int) fileResult {
	return fileResult{
		idx: idx,
		pending: &pendingPut{
			key:       Key{SourceID: "s", NativePath: fmt.Sprintf("/f%d", idx)},
			objectKey: fmt.Sprintf("v1/o/%d.age", idx),
			obj:       make([]byte, size),
			md:        map[string]string{"source-hash": "deadbeef"},
		},
	}
}

// run stages every size and drains every group the accumulator produced.
func stageAll(t *testing.T, sizes []int) [][]int {
	t.Helper()
	ctx := context.Background()
	port := &sizePort{}
	p := &sourcePass{o: Options{Upload: port}}
	// Buffered past the group count, so the accumulator's send never blocks the staging loop.
	batches := make(chan []fileResult, len(sizes)+1)
	p.staged = &batcher{
		maxObjects: maxBatchObjects,
		send:       func(items []fileResult) { batches <- p.o.sendBatch(ctx, items) },
	}

	for i, sz := range sizes {
		if done, final := p.stageUpload(stagedFor(i, sz)); final {
			t.Fatalf("object %d was not staged: %+v", i, done.outcome)
		}
	}
	p.staged.flush()
	for seen := 0; seen < len(sizes); {
		done := <-batches
		for _, result := range done {
			assert.Nil(t, result.pending, "completed results must release ciphertext")
		}
		seen += len(done)
	}
	port.mu.Lock()
	defer port.mu.Unlock()
	return port.groups
}

// Both bounds hold at once, and every object is authorized exactly once across the groups.
func TestTheAuthorizationGroupIsBoundedByBytesAndByCount(t *testing.T) {
	tiny := make([]int, 70)
	for i := range tiny {
		tiny[i] = 1 << 10
	}
	cases := []struct {
		name  string
		sizes []int
	}{
		{"count", tiny},
		{"bytes", []int{40 << 20, 30 << 20, 10 << 20}},
		{"one object over the whole bound rides alone", []int{70 << 20, 1 << 10}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			groups := stageAll(t, c.sizes)
			objects := 0
			for _, g := range groups {
				bytes := 0
				for _, sz := range g {
					bytes += sz
				}
				assert.Truef(t, len(g) <= maxBatchObjects, "a group carried %d objects, over the %d bound", len(g), maxBatchObjects)
				// An object larger than the whole bound is the one exception, and it rides alone.
				assert.Truef(t, bytes <= maxBatchBytes || len(g) == 1, "a group of %d carried %d bytes, over the %d bound", len(g), bytes, maxBatchBytes)
				objects += len(g)
			}
			assert.Equalf(t, len(c.sizes), objects, "%d objects authorized for %d staged", objects, len(c.sizes))
		})
	}
}

// Exercise both stop paths without relying on worker timing to leave a partly filled batch.
func TestStoppedUploadsReleaseCiphertext(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		t.Run(fmt.Sprintf("fatal=%t", fatal), func(t *testing.T) {
			p := &sourcePass{fatal: fatal, uploadHalted: !fatal, staged: &batcher{maxObjects: maxBatchObjects}}
			p.staged.add(stagedFor(0, 1))
			newResult, final := p.stageUpload(stagedFor(1, 1))
			require.True(t, final, "a stopped pass must not enqueue new uploads")
			drained := p.drainStaged()
			require.Len(t, drained, 1)
			for i, result := range append(drained, newResult) {
				assert.Equal(t, i, result.idx)
				assert.Nil(t, result.pending, "abandoned results must release ciphertext")
				assert.Equal(t, "failed", string(result.outcome.Decision))
				assert.Equal(t, fatal, result.outcome.Fatal)
				assert.Equal(t, !fatal, result.unavailable)
			}
			assert.Empty(t, p.staged.items)
		})
	}
}
