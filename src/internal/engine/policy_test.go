package engine_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Preview computes everything that would leave the machine, and neither authorizes nor commits.
func TestPreviewAuthorizesNothingAndCommitsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/d%02d.jsonl", 3)

	rep := f.run(dryRun)

	assert.Equalf(t, 3, rep.Shipped, "preview should report what would ship: %+v", rep)
	assert.Empty(t, f.port.sizes(), "preview authorized something")
	assert.Equal(t, 0, f.store.Len(), "preview committed state")
	// The plan must carry the real object key and sealed size, or it previews nothing.
	for _, file := range rep.Sources[0].Files {
		assert.NotEqual(t, "", file.ObjectKey, "preview should report the object key that would be used")
		assert.NotEqual(t, int64(0), file.BytesOut, "preview should report the sealed size")
	}
}

// Budget is reserved at admission, so parallel files cannot overshoot it; the rest arrive next
// tick, and the drain ignores the bound because a backlog left behind at shutdown is data loss.
func TestMaxFilesPerRunAndTheDrain(t *testing.T) {
	f := newFixture(t)
	f.writeTranscripts("p/s%d.jsonl", 7)
	f.plan.MaxFilesPerRun = 2

	for tick := 1; tick <= 2; tick++ {
		rep := f.run(workers(8, 0))
		assert.Equalf(t, 2, rep.Shipped, "tick %d: budget 2 shipped %d files", tick, rep.Shipped)
		assert.True(t, rep.Truncated, "a truncated run must say so")
		assert.Len(t, f.port.keys(), 2*tick)
	}

	f.reopen()
	drained := f.run(func(o *engine.Options) { o.Unbounded = true })
	assert.False(t, drained.Truncated, "the drain reported itself truncated: the bound still applied")
	assert.Equal(t, 3, drained.Shipped, "the drain must ship everything that was left")
	assert.Equal(t, 4, drained.Unchanged, "the already-shipped files must be recognised as unchanged")
}

func TestDisabledSourceIsNotCollected(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.plan.Sources[0].Enabled = false

	rep := f.run()
	assert.Truef(t, rep.Shipped == 0 && len(f.port.keys()) == 0, "a disabled source must not be collected: %+v", rep)
}

func TestRunRefusesWithoutRecipients(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	o.Recipients = nil
	_, runErr := engine.Run(context.Background(), f.store, o)
	require.Error(t, runErr, "a run with no recipients must be refused: encryption is not optional")
}

// Expiry is recorded per object because the archive outlives the collection run.
func TestConfigExpiryIsStampedOnEveryManifest(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			f := newFixture(t)
			f.plan.ConfigExpired = expired
			f.writeTranscript("p/s1.jsonl", line1)
			f.writeTranscript("p/s2.jsonl", line2)
			require.Equal(t, 2, f.run().Shipped)
			for _, k := range f.port.keys() {
				_, m, _ := f.openObject(t, k)
				assert.Equal(t, expired, m.ConfigExpired, k)
			}
		})
	}
}

// Pause blocks normal runs and drains without consuming state; preview stays available, then resume sends the backlog.
func TestPauseLifecycle(t *testing.T) {
	for _, reason := range []string{"", "off to a client site"} {
		t.Run("reason="+reason, func(t *testing.T) {
			f := newFixture(t)
			f.writeTranscript("p/s1.jsonl", line1)
			require.NoError(t, platform.Set(f.stateDir, reason, engineFixedTime(), time.Time{}))
			for _, unbounded := range []bool{false, true} {
				rep := f.run(func(o *engine.Options) { o.Unbounded = unbounded })
				assert.True(t, rep.Paused)
				assert.Equal(t, reason, rep.PauseReason)
				assert.Zero(t, rep.Shipped)
				assert.Empty(t, f.port.keys())
				f.reopen()
				doc, err := engine.Peek(f.stateDir)
				require.NoError(t, err)
				assert.Empty(t, doc.Entries, "paused runs must not consume the backlog")
			}

			preview := f.run(dryRun)
			assert.False(t, preview.Paused)
			assert.Equal(t, 1, preview.Shipped)
			assert.Empty(t, f.port.keys())
			assert.Zero(t, f.store.Len())

			require.NoError(t, platform.Clear(f.stateDir))
			rep := f.run()
			assert.False(t, rep.Paused)
			assert.Equal(t, 1, rep.Shipped, "resume must collect the held backlog")
		})
	}
}
