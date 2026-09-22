//go:build perf

// The measurements themselves. No t.Parallel anywhere, ever: the package shares one proxy and
// one protocol peer, and a toxic is global to it. Every bound is relative (a multiple of the
// injected RTT, or a ratio between two runs), never an absolute time.
package perf

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// A plausible cross-region hop, far enough above loopback noise to not be an artifact.
const shapedRTT = 50 * time.Millisecond

// Selects only what came off the machine; the heartbeat and project map change every run by design.
const transcriptPrefix = "mirror/source=claude-code-transcripts/"

// The claim the upload pool exists for: a backlog against a store 50ms away must not cost one
// round trip per file. Structure is compared first, since a "faster" run that shipped fewer files
// is not faster; each side is the minimum of two samples, because noise only ever adds. The rows
// walk the bound up the latency scale; -short runs only the first, since each is a full backlog.
func TestBacklogFirstSyncOverlapsRoundTrips(t *testing.T) {
	base, files, baseObs := backlogSync(t)
	baseCounts := summary(t, baseObs.Output)
	baseElapsed := min(baseObs.Elapsed, timingRun(t))
	baseKeys := base.currentKeys(t)

	rtts := []time.Duration{shapedRTT, 200 * time.Millisecond}
	if testing.Short() {
		rtts = rtts[:1]
	}
	for _, rtt := range rtts {
		t.Run(fmt.Sprintf("rtt=%v", rtt), func(t *testing.T) {
			withLatency(t, rtt)

			shaped, _, shapedObs := backlogSync(t)
			shapedCounts := summary(t, shapedObs.Output)
			shapedElapsed := min(shapedObs.Elapsed, timingRun(t))

			assertSameKeys(t, baseKeys, shaped.currentKeys(t))
			for _, k := range summaryWords {
				if baseCounts[k] != shapedCounts[k] {
					t.Errorf("%s: %d unshaped, %d shaped; the two runs did different work",
						k, baseCounts[k], shapedCounts[k])
				}
			}

			added := shapedElapsed - baseElapsed
			// One round trip per file over half the compute pool: slack for a loaded machine, still far
			// under the serial cost. The logged overlap ratio is the sharper statement.
			bound := time.Duration(files) * rtt / (childGOMAXPROCS / 2)

			serial := time.Duration(files) * rtt
			t.Logf("backlog %d files: unshaped %v, shaped at %v rtt %v, added %v (bound %v, overlap %.1fx)",
				files, baseElapsed.Round(time.Millisecond), rtt,
				shapedElapsed.Round(time.Millisecond), added.Round(time.Millisecond), bound,
				float64(serial)/float64(max(added, time.Millisecond)))

			if added >= bound {
				t.Errorf("%v of latency on %d files added %v, over the %v bound: "+
					"the run is paying round trips one at a time", rtt, files, added, bound)
			}
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

	t.Logf("steady state: backlog %v / %d bytes, second run %v / %d bytes",
		backlog.Elapsed.Round(time.Millisecond), backlogBytes,
		steady.Elapsed.Round(time.Millisecond), steadyBytes)

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

// The second sample of a measurement, so no bound ever rests on a single wall clock.
func timingRun(t *testing.T) time.Duration {
	t.Helper()
	_, _, obs := backlogSync(t)
	return obs.Elapsed
}

// Two runs are comparable only if they landed the same objects; the keys are install-relative.
func assertSameKeys(t *testing.T, a, b []string) {
	t.Helper()
	slices.Sort(a)
	slices.Sort(b)
	if len(a) != len(b) {
		t.Fatalf("the two runs landed %d and %d keys", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("the two runs disagree at key %d: %q and %q", i, a[i], b[i])
		}
	}
}

// The floor is not zero (config fetch, heartbeat, project map), so the claims are ratios.
func assertSteadyState(t *testing.T, files, unchanged int, moved, backlogBytes int64, elapsed, backlogElapsed time.Duration) {
	t.Helper()
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

// An unchanged file must not be re-shipped by the runs after the backlog.
func (w *world) assertTranscriptVersions(t *testing.T, afterBacklog map[string]int) {
	t.Helper()
	for key, after := range w.versionCounts(t) {
		if !strings.Contains(key, transcriptPrefix) {
			continue
		}
		if before := afterBacklog[key]; after != before {
			t.Errorf("%s: %d versions after the backlog, %d after the later runs; "+
				"an unchanged file was re-shipped", key, before, after)
		}
	}
}
