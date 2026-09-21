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
	"github.com/QuesmaOrg/quesma-shipper/internal/transforms"
)

// preview computes everything that would leave the machine and does neither upload nor commit.
func TestPreviewUploadsNothingAndCommitsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)

	o := f.opts()
	o.DryRun = true
	rep, err := engine.Run(context.Background(), f.store, o)
	require.NoError(t, err)

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
	if _, err := engine.Run(context.Background(), f.store, o); err == nil {
		t.Fatal("a run with no recipients must be refused: encryption is not optional")
	}
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
				obj, _ := f.port.get(k)
				m, _, err := transforms.Open(obj.Body, f.unit.Identity)
				require.NoError(t, err)
				assert.Equal(t, expired, m.ConfigExpired, k)
			}
		})
	}
}

// A paused install collects nothing, ships nothing, and commits nothing. Checked at the engine
// rather than per verb: a per-verb check would be one new verb away from a hole.
func TestAPausedInstallShipsNothingAndCommitsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	require.NoError(t, platform.Set(f.stateDir, "off to a client site", engineFixedTime(), time.Time{}))

	rep := f.run()
	assert.True(t, rep.Paused, "the report does not say paused; a zero summary reads as nothing to collect")
	assert.NotEqual(t, "", rep.PauseReason, "the reason did not reach the report")
	if rep.Shipped != 0 || len(f.port.keys()) != 0 {
		t.Fatalf("a paused install shipped: %+v %v", rep, f.port.keys())
	}

	// Nothing committed either, or resuming would treat never-shipped files as already sent.
	f.reopen()
	doc, err := engine.Peek(f.stateDir)
	require.NoError(t, err)
	require.Lenf(t, doc.Entries, 0, "a paused run committed %d fingerprints; resuming would skip those files", len(doc.Entries))
}

func TestResumingCollectsTheBacklogThePauseHeldBack(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	require.NoError(t, platform.Set(f.stateDir, "", engineFixedTime(), time.Time{}))
	f.run()

	require.NoError(t, platform.Clear(f.stateDir))
	rep := f.run()
	require.True(t, !rep.Paused, "still paused after Clear")
	require.NotEqual(t, 0, rep.Shipped, "resuming shipped nothing: the paused run must not have consumed the backlog")
}

// preview is exempt: it uploads and commits nothing, and a paused owner may still look.
func TestPreviewStillWorksWhilePaused(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	require.NoError(t, platform.Set(f.stateDir, "", engineFixedTime(), time.Time{}))

	rep := f.runDry()
	assert.True(t, !rep.Paused, "preview reported itself paused")
	assert.NotEqual(t, 0, rep.Shipped, "preview found nothing to show while paused")
	assert.Lenf(t, f.port.keys(), 0, "preview uploaded %v", f.port.keys())
}

// The drain ignores max_files_per_run: it runs when the host is about to disappear, and with no
// spool a backlog left behind is data loss rather than a catch-up next tick.
func TestDrainIgnoresTheMaxFilesPerRunBound(t *testing.T) {
	f := newFixture(t)
	f.eff.MaxFilesPerRun = 2
	for i := 0; i < 7; i++ {
		f.writeTranscript(fmt.Sprintf("p/s%d.jsonl", i), line1)
	}

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

func TestADrainOnAPausedInstallStillShipsNothing(t *testing.T) {
	f := newFixture(t)
	f.writeTranscript("p/s1.jsonl", line1)
	require.NoError(t, platform.Set(f.stateDir, "", engineFixedTime(), time.Time{}))

	// The drain gets no exception: switching collection off is not consent to a last upload.
	rep := f.runUnbounded()
	if !rep.Paused || rep.Shipped != 0 || len(f.port.keys()) != 0 {
		t.Fatalf("a drain overrode the pause: %+v %v", rep, f.port.keys())
	}
}
