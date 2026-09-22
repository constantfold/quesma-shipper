//go:build perf

// The tier CI runs: a three-minute budget on a shared runner makes it a different design, not a
// smaller copy. One machine, a tenth of the backlog, the child held to two cores, and the minimum
// of repetitions as the answer. Counters are checked tightly, the clock second; the two tiers never compare.
package perf

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// A tenth of the full tier's backlog; lower and process start becomes a visible share of it.
	smokeCorpusFiles = 1024

	smokeGOMAXPROCS = 2
	smokeRTT        = shapedRTT

	// Fewer on the baseline: the bound is shaped minus unshaped, and the shaped side is what noise can fail.
	smokeBaselineReps = 2
	smokeReps         = 3

	// The engine's shape S1's bound derives from: rounds of admission*GOMAXPROCS files, PUT fanout*GOMAXPROCS
	// wide, nothing admitted while a group is out. A pipeline that changes shape must move these.
	smokeAdmissionFactor = 5
	smokePutFanoutFactor = 4
)

// One admission round's files and the waves of PUTs it costs, assuming one authorization group.
const (
	smokeRoundFiles = smokeAdmissionFactor * smokeGOMAXPROCS
	smokePutWidth   = smokePutFanoutFactor * smokeGOMAXPROCS
	smokeRoundTrips = (smokeRoundFiles + smokePutWidth - 1) / smokePutWidth
)

// A heartbeat, project map, and Claude account snapshot.
const smokeSidecarObjects = 3

// Measured, and narrow: two runs of unchanged code over this corpus agree to within an HTTP header.
const (
	// One S3 call per file plus sidecars: catches an extra call per file or none at all, allowing the odd retry.
	smokeRequestsPerFileMin = 0.95
	smokeRequestsPerFileMax = 1.30

	// Wire bytes over logical: catches a run that started putting the corpus on the wire twice.
	smokeWireRatioMax = 0.85
)

// PROVISIONAL: about twice a laptop observation, headroom for the reading darwin cannot take, not slack for
// the code. They say "nothing has grown much"; loosening one to make a run pass is what they exist to stop.
const (
	smokeBacklogBudget int64 = 128 << 20
	smokeSteadyBudget  int64 = 96 << 20
)

type smokeMachine struct {
	w     *world
	files int
	bytes int // the corpus on disk: the denominator of the wire ratio
}

// The whole CI tier in one test, because S2 measures the sync after S1's backlog on the same machine.
func TestSmokeTier(t *testing.T) {
	m := stageSmokeMachine(t)

	// The unshaped reference and the tier's warm-up, absorbing a fresh runner's cold caches once.
	baseline := smokeBaseline(t, m)

	withLatency(t, smokeRTT)

	backlog := smokeBacklog(t, m, baseline)
	smokeSteady(t, m, backlog)

	// The resource guards last, on their own machines, so their far bigger files cannot disturb the timings.
	smokeBigFileAcceptance(t)
	smokeBigFile(t)
	smokeInFlightCap(t)
	smokeScrubGuard(t)
	smokeSingleLine(t)
	smokeSingleLineSecrets(t)
}

// The same backlog with nothing on the wire: subtracting it leaves S1's bound about round trips.
func smokeBaseline(t *testing.T, m *smokeMachine) time.Duration {
	t.Helper()
	m.w.reset(t)
	m.w.mustSync(t)

	reps := make([]time.Duration, 0, smokeBaselineReps)
	for range smokeBaselineReps {
		m.w.reset(t)
		obs := m.w.mustSync(t)
		require.GreaterOrEqual(t, summary(t, obs.Output)["shipped"], m.files, "the baseline run shipped too few files")
		reps = append(reps, obs.Elapsed)
	}
	best := slices.Min(reps)
	t.Logf("unshaped baseline on %d files: reps %s, best %v",
		m.files, durationList(reps), best.Round(time.Millisecond))
	return best
}

// What S2 needs from S1: the run it compares itself against.
type smokeBacklogResult struct {
	best     time.Duration
	bytes    int64
	versions map[string]int
}

// A first sync over the shaped link; every repetition is cold, or it would be measuring S2.
func smokeBacklog(t *testing.T, m *smokeMachine, baseline time.Duration) smokeBacklogResult {
	var result smokeBacklogResult
	t.Run("S1-backlog-first-sync", func(t *testing.T) {
		meas := smokeRepeat(t, m, coldRuns)
		counts := summary(t, meas.last.Output)
		moved := meas.counters.up + meas.counters.down
		result = smokeBacklogResult{best: meas.best, bytes: moved, versions: m.w.versionCounts(t)}

		// Half the overlap an admission round can reach (the round, not the per-group upload pool).
		added := meas.best - baseline
		serial := time.Duration(m.files) * smokeRTT
		bound := serial * 2 * smokeRoundTrips / smokeRoundFiles

		perFile := float64(meas.counters.requests) / float64(m.files)
		ratio := float64(moved) / float64(m.bytes)
		t.Logf("S1 backlog %d files at %v rtt: reps %s, best %v against a %v baseline, added %v "+
			"(bound %v on a serial %v, %.1fx overlap)",
			m.files, smokeRTT, durationList(meas.reps), meas.best.Round(time.Millisecond),
			baseline.Round(time.Millisecond), added.Round(time.Millisecond), bound, serial,
			float64(serial)/float64(max(added, time.Millisecond)))
		t.Logf("S1 counters: %d objects, %d S3 requests (%.2f per file), %d bytes up and %d down "+
			"on %d logical (%.3f wire ratio)",
			meas.objects, meas.counters.requests, perFile, meas.counters.up, meas.counters.down,
			m.bytes, ratio)

		row := meas.row(m.w, smokeBacklogScenario, m.files, m.bytes, smokeBacklogBudget)
		row.BaselineSeconds = baseline.Seconds()
		recordResult(t, row)

		require.GreaterOrEqual(t, counts["shipped"], m.files, "the backlog run shipped too few files")
		require.Zerof(t, counts["failed"], "the backlog run failed files:\n%s", meas.last.Output)

		assert.Lessf(t, added, bound, "%v of latency on %d files: the run is paying round trips one at a time", smokeRTT, m.files)
		assert.Truef(t, perFile >= smokeRequestsPerFileMin && perFile <= smokeRequestsPerFileMax,
			"the backlog made %d S3 requests for %d files, %.2f each, outside the %.2f to %.2f band",
			meas.counters.requests, m.files, perFile, smokeRequestsPerFileMin, smokeRequestsPerFileMax)
		assert.LessOrEqualf(t, ratio, smokeWireRatioMax, "the backlog's wire bytes over %d logical bytes", m.bytes)
		assert.Equalf(t, m.files+smokeSidecarObjects, meas.objects, "objects under %s (%d files and %d sidecars)",
			m.w.keyRoot, m.files, smokeSidecarObjects)

		assertNoResidualScratch(t, m.w)
		assertPeakUnderBudget(t, smokeBacklogScenario, meas.peak, smokeBacklogBudget)
	})
	return result
}

// What a machine with nothing to do costs, measured on the world S1 left behind.
func smokeSteady(t *testing.T, m *smokeMachine, backlog smokeBacklogResult) {
	t.Run("S2-incremental-no-op-sync", func(t *testing.T) {
		if backlog.best <= 0 || backlog.bytes <= 0 || backlog.versions == nil {
			t.Skipf("S2 measures the sync after S1's backlog and S1 left no baseline behind: "+
				"run %s whole", t.Name())
		}

		// The first no-op run discovers there is nothing to do; the timed ones measure the steady state.
		m.w.mustSync(t)

		meas := smokeRepeat(t, m, warmRuns)
		t.Logf("S2 steady state on %d files: reps %s, %d S3 requests",
			m.files, durationList(meas.reps), meas.counters.requests)

		// Recorded before anything is judged: a failed run is the one worth having numbers for.
		recordResult(t, meas.row(m.w, smokeSteadyScenario, m.files, m.bytes, smokeSteadyBudget))

		assertSteadyState(t, m.files, summary(t, meas.last.Output)["unchanged"],
			meas.counters.up+meas.counters.down, backlog.bytes, meas.best, backlog.best)
		m.w.assertTranscriptVersions(t, backlog.versions)

		// Rewriting the heartbeat and project map is where an unrenamed temp file would show up.
		assertNoResidualScratch(t, m.w)
		assertPeakUnderBudget(t, smokeSteadyScenario, meas.peak, smokeSteadyBudget)
	})
}

const (
	coldRuns = true
	warmRuns = false
)

// What a run of repetitions came to.
type smokeMeasurement struct {
	reps []time.Duration
	best time.Duration

	last childObservation // the repetition the counters were read around
	peak childObservation // the highest: a spike in any repetition is the finding

	counters storeCounters
	objects  int
}

// One unrepeated run as a measurement, so every scenario records its row the same way.
func singleRun(obs childObservation, c storeCounters, objects int) smokeMeasurement {
	return smokeMeasurement{reps: []time.Duration{obs.Elapsed}, best: obs.Elapsed, last: obs, peak: obs, counters: c, objects: objects}
}

func (meas smokeMeasurement) row(w *world, scenario string, files, bytes int, budget int64) perfResult {
	return perfResult{
		Scenario:          scenario,
		CorpusFiles:       files,
		CorpusBytes:       bytes,
		ChildGOMAXPROCS:   w.gomaxprocs,
		ShapedRTTMillis:   smokeRTT.Milliseconds(),
		RepSeconds:        repSeconds(meas.reps),
		BestSeconds:       meas.best.Seconds(),
		ProxiedBytesUp:    meas.counters.up,
		ProxiedBytesDown:  meas.counters.down,
		S3Requests:        meas.counters.requests,
		Objects:           meas.objects,
		PeakRSSBytes:      meas.peak.PeakRSS,
		PeakRSSSource:     meas.peak.PeakRSSSource,
		MemoryBudgetBytes: budget,
		CPUSeconds:        meas.last.CPUSeconds,
		ExitStatus:        meas.last.exitStatus(),
	}
}

// cold resets the world before each repetition; counters are read around the last one only, as scrapes are slow.
func smokeRepeat(t *testing.T, m *smokeMachine, cold bool) smokeMeasurement {
	t.Helper()
	var meas smokeMeasurement
	sync := func() { meas.last = m.w.mustSync(t) }
	for rep := range smokeReps {
		if cold {
			m.w.reset(t)
		}
		if rep == smokeReps-1 {
			meas.counters = aroundStore(t, sync)
		} else {
			sync()
		}
		meas.reps = append(meas.reps, meas.last.Elapsed)
		if meas.last.PeakRSS > meas.peak.PeakRSS {
			meas.peak = meas.last
		}
	}
	meas.best = slices.Min(meas.reps)
	meas.objects = len(m.w.currentKeys(t))
	return meas
}

func stageSmokeMachine(t *testing.T) *smokeMachine {
	t.Helper()
	w := stageSmokeWorld(t)
	bytes := stageCorpusFiles(t, w, smokeCorpusFiles)
	t.Logf("smoke corpus: %d files, %d bytes staged, child at GOMAXPROCS=%d",
		smokeCorpusFiles, bytes, w.gomaxprocs)
	return &smokeMachine{w: w, files: smokeCorpusFiles, bytes: bytes}
}

func durationList(ds []time.Duration) string {
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.Round(time.Millisecond).String()
	}
	return strings.Join(parts, " ")
}

func repSeconds(ds []time.Duration) []float64 {
	out := make([]float64, len(ds))
	for i, d := range ds {
		out[i] = d.Seconds()
	}
	return out
}
