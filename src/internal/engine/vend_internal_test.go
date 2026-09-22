package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The authorization accumulator, exercised directly: the byte bound needs objects too large to
// produce through the loop, and overshooting it loses a whole group.

// okPort confirms every object.
type okPort struct{}

func (okPort) AuthorizeAndUpload(_ context.Context, batch []PreparedObject) []error {
	return make([]error, len(batch))
}

// stagedFor is one sealed object of a given size.
func stagedFor(idx, size int) fileResult {
	return fileResult{
		idx:     idx,
		outcome: FileOutcome{ObjectKey: fmt.Sprintf("v1/o/%d.age", idx)},
		pending: &pendingPut{
			obj: make([]byte, size),
			md:  map[string]string{"source-hash": "deadbeef"},
		},
	}
}

// stageAll stages every size and returns the ciphertext sizes of each group sent.
func stageAll(t *testing.T, sizes []int) [][]int {
	t.Helper()
	var groups [][]int
	p := &sourcePass{o: Options{Upload: okPort{}}}
	p.staged = &batcher{
		maxObjects: maxBatchObjects,
		send: func(items []fileResult) {
			var g []int
			for _, it := range items {
				g = append(g, len(it.pending.obj))
			}
			groups = append(groups, g)
			for _, r := range p.o.sendBatch(context.Background(), items) {
				assert.Nil(t, r.pending, "completed results must release ciphertext")
			}
		},
	}
	for i, sz := range sizes {
		_, final := p.stageUpload(stagedFor(i, sz))
		require.False(t, final, "object %d was not staged", i)
	}
	p.staged.flush()
	return groups
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
