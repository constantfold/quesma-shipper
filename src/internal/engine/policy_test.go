package engine_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// Budget is reserved at admission so parallel files cannot overshoot it; the drain ignores the bound.
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
	_, err := newFixture(t).try(func(o *engine.Options) { o.Recipients = nil })
	require.Error(t, err, "a run with no recipients must be refused: encryption is not optional")
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

// Pause blocks runs and drains without consuming state; preview still works, and resume sends the backlog.
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

			// Preview computes the real key and sealed size, and neither authorizes nor commits.
			preview := f.run(dryRun)
			assert.False(t, preview.Paused)
			assert.Equal(t, 1, preview.Shipped)
			assert.Empty(t, f.port.sizes(), "preview authorized something")
			assert.Zero(t, f.store.Len())
			fo := preview.Sources[0].Files[0]
			assert.Truef(t, fo.ObjectKey != "" && fo.BytesOut != 0, "preview did not report the key and sealed size: %+v", fo)

			require.NoError(t, platform.Clear(f.stateDir))
			rep := f.run()
			assert.False(t, rep.Paused)
			assert.Equal(t, 1, rep.Shipped, "resume must collect the held backlog")
		})
	}
}
