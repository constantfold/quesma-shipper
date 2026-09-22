//go:build perf

// The measurements themselves. No t.Parallel anywhere, ever: the package shares one proxy and
// one protocol peer, and a toxic is global to it. Every bound is relative (a multiple of the
// injected RTT, or a ratio between two runs), never an absolute time.
package perf

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A plausible cross-region hop, far enough above loopback noise to not be an artifact.
const shapedRTT = 50 * time.Millisecond

// Selects only what came off the machine; the heartbeat and project map change every run by design.
const transcriptPrefix = "mirror/source=claude-code-transcripts/"

// The claim the upload pool exists for: a backlog against a store 50ms away must not cost one
// round trip per file. Structure is compared first, since a "faster" run that shipped fewer files
// is not faster.
func TestBacklogFirstSyncOverlapsRoundTrips(t *testing.T) {
	base, files, baseObs := backlogSync(t)
	baseElapsed := min(baseObs.Elapsed, timingRun(t))

	withLatency(t, shapedRTT)

	shaped, _, shapedObs := backlogSync(t)
	shapedElapsed := min(shapedObs.Elapsed, timingRun(t))

	baseKeys, shapedKeys := base.currentKeys(t), shaped.currentKeys(t)
	slices.Sort(baseKeys)
	slices.Sort(shapedKeys)
	require.Equal(t, baseKeys, shapedKeys, "the two runs landed different object keys")
	assert.Equal(t, summary(t, baseObs.Output), summary(t, shapedObs.Output), "the two runs did different work")

	assertOverlapsRoundTrips(t, files, shapedRTT, baseElapsed, shapedElapsed)
}

// Walks the bound up the latency scale: one rtt could be a coincidence, the curve is the evidence.
// Skipped under -short: it is the whole tier again, once per row.
func TestLatencySensitivity(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: the sensitivity table runs a full backlog per row")
	}
	baseline := min(timingRun(t), timingRun(t))
	t.Logf("unshaped baseline: %v for %d files", baseline.Round(time.Millisecond), corpusFiles)

	for _, rtt := range []time.Duration{50 * time.Millisecond, 200 * time.Millisecond} {
		t.Run(fmt.Sprintf("rtt=%v", rtt), func(t *testing.T) {
			withLatency(t, rtt)
			assertOverlapsRoundTrips(t, corpusFiles, rtt, baseline, min(timingRun(t), timingRun(t)))
		})
	}
}

// A machine whose backlog is already shipped must cost almost nothing, however far the store is.
func TestSteadyStateSyncMakesAlmostNoNetworkCalls(t *testing.T) {
	withLatency(t, shapedRTT)

	// The byte counters run for the life of the tier; staging a world moves nothing through them.
	before := proxiedBytes(t)
	w, files, backlog := backlogSync(t)
	backlogBytes := proxiedBytes(t) - before
	versionsAfterBacklog := w.versionCounts(t)

	steady := w.mustSync(t)
	steadyBytes := proxiedBytes(t) - before - backlogBytes

	assertSteadyState(t, files, summary(t, steady.Output)["unchanged"],
		steadyBytes, backlogBytes, steady.Elapsed, backlog.Elapsed)
	w.assertTranscriptVersions(t, versionsAfterBacklog)
}

// One first sync of the whole corpus on a fresh world.
func backlogSync(t *testing.T) (*world, int, childObservation) {
	t.Helper()
	w := stageWorld(t)
	files := stageCorpus(t, w)
	obs := w.mustSync(t)
	if got := summary(t, obs.Output)["shipped"]; got < files {
		t.Fatalf("the backlog run shipped %d of %d files", got, files)
	}
	return w, files, obs
}

// A second sample, so no bound ever rests on a single wall clock; callers take the minimum of two,
// because noise only ever adds.
func timingRun(t *testing.T) time.Duration {
	t.Helper()
	_, _, obs := backlogSync(t)
	return obs.Elapsed
}

// One round trip per file over half the compute pool: slack for a loaded machine, still far under
// the serial cost. The logged overlap ratio is the sharper statement.
func assertOverlapsRoundTrips(t *testing.T, files int, rtt, baseline, shaped time.Duration) {
	t.Helper()
	added := shaped - baseline
	serial := time.Duration(files) * rtt
	bound := serial / (childGOMAXPROCS / 2)
	t.Logf("backlog %d files: unshaped %v, shaped at %v rtt %v, added %v (bound %v, overlap %.1fx on a serial %v)",
		files, baseline.Round(time.Millisecond), rtt, shaped.Round(time.Millisecond),
		added.Round(time.Millisecond), bound, float64(serial)/float64(max(added, time.Millisecond)), serial)
	if added >= bound {
		t.Errorf("%v of latency on %d files added %v, over the %v bound: "+
			"the run is paying round trips one at a time", rtt, files, added, bound)
	}
}

// The floor of a sync with nothing to do is not zero (config fetch, heartbeat, project map), so the
// claims are ratios against the backlog that preceded it.
func assertSteadyState(t *testing.T, files, unchanged int, moved, backlogBytes int64, elapsed, backlogElapsed time.Duration) {
	t.Helper()
	t.Logf("steady state: backlog %v / %d bytes, second run %v / %d bytes",
		backlogElapsed.Round(time.Millisecond), backlogBytes, elapsed.Round(time.Millisecond), moved)
	if unchanged < files {
		t.Errorf("the second run called %d files unchanged, want at least %d: "+
			"the pre-filter is opening files it does not need to", unchanged, files)
	}
	if moved*20 >= backlogBytes {
		t.Errorf("the second run moved %d bytes against the backlog's %d, over a twentieth: "+
			"an unchanged machine is still talking to the store", moved, backlogBytes)
	}
	if elapsed*3 >= backlogElapsed {
		t.Errorf("the second run took %v against the backlog's %v, over a third: "+
			"discovery is costing what shipping cost", elapsed, backlogElapsed)
	}
}
