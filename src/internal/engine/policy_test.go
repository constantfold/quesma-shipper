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

// preview computes everything that would leave the machine and does neither upload nor commit.
func TestPreviewUploadsNothingAndCommitsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	rep := f.runDry()

	assert.Equalf(t, 1, rep.Shipped, "preview should report what would ship: %+v", rep)
	assert.Len(t, f.port.keys(), 0, "preview uploaded something")
	assert.Equal(t, 0, f.store.Len(), "preview committed state")

	// The plan must carry the real object key and redaction figures, or it previews nothing.
	file := rep.Sources[0].Files[0]
	assert.NotEqual(t, "", file.ObjectKey, "preview should report the object key that would be used")
	assert.NotEqual(t, int64(0), file.BytesOut, "preview should report the sealed size")
}

func TestMaxFilesPerRunIsReportedNotSilent(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"p/a.jsonl", "p/b.jsonl", "p/c.jsonl", "p/d.jsonl"} {
		f.writeTranscript(p, line1)
	}
	f.eff.MaxFilesPerRun = 2

	rep := f.run()
	assert.Equalf(t, 2, rep.Shipped, "expected the run to stop at 2, got %d", rep.Shipped)
	assert.True(t, rep.Truncated, "a truncated run must say so")

	// The rest arrive on the next tick: a bound is a catch-up, not a loss.
	rep2 := f.run()
	assert.Equalf(t, 2, rep2.Shipped, "the remaining files should ship next tick, got %d", rep2.Shipped)
	assert.Lenf(t, f.port.keys(), 4, "expected 4 objects, got %d", len(f.port.keys()))
}

func TestDisabledSourceIsNotCollected(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	f.eff.Sources[0].Enabled = false

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
			f.eff.ConfigExpired = expired
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

			preview := f.runDry()
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

// The drain ignores max_files_per_run: it runs when the host is about to disappear, and with no
// spool a backlog left behind is data loss rather than a catch-up next tick.
func TestDrainIgnoresTheMaxFilesPerRunBound(t *testing.T) {
	f := newFixture(t)
	f.eff.MaxFilesPerRun = 2
	f.writeTranscripts("p/s%d.jsonl", 7)

	bounded := f.run()
	require.Truef(t, bounded.Truncated, "a bound of 2 did not truncate 7 files: %+v", bounded)
	require.Truef(t, bounded.Shipped <= 2, "the bound was not applied: shipped %d", bounded.Shipped)

	f.reopen()
	drained := f.runUnbounded()
	assert.True(t, !drained.Truncated, "the drain reported itself truncated: the bound still applied")
	// Everything that was left, in one pass.
	assert.Truef(t, drained.Shipped >= 5, "the drain shipped %d of the remaining files", drained.Shipped)
	assert.NotEqual(t, 0, drained.Unchanged, "the already-shipped files were re-shipped rather than recognised as unchanged")
}
