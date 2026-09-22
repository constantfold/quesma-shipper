//go:build perf

// Memory scenarios and their resource budgets.
package perf

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The harness consumes a binary; assertInFlightCapIsWired checks this literal reaches it.
const envMaxInFlightBytes = "SHIPPER_MAX_IN_FLIGHT_BYTES"

// S3's acceptance gate: the requirement, not a measurement; see smokeBigFileAcceptance.
const (
	acceptanceFileBytes int64 = 500 << 20
	acceptanceBudget    int64 = 200 << 20
)

// The bounded 32 MiB interim guard catches doubling; its provisional budget may only tighten.
const (
	bigFileBytes  int64 = 32 << 20
	bigFileBudget int64 = 416 << 20
)

// No two files fit together under the override, forcing serial admission.
const (
	inFlightCap       int64 = 12 << 20
	inFlightFileBytes int64 = 8 << 20
	inFlightFiles           = 4

	// Between the serial and concurrent peaks, so a broken gate fails this budget.
	inFlightBudget int64 = 208 << 20
)

// PROVISIONAL on the same terms as bigFileBudget, and gating for the first time where VmHWM exists.
const (
	singleLineFileBytes int64 = 50 << 20
	singleLineBudget    int64 = 250 << 20
	// Dirty strings coexist as source, decoded text, replacement and output.
	singleLineDirtyBudget int64 = 320 << 20
)

// Streaming acceptance remains skipped until the pipeline can meet the declared memory bound.
func smokeBigFileAcceptance(t *testing.T) {
	t.Run("S3-big-file-acceptance", func(t *testing.T) {
		t.Skipf("the acceptance gate for streaming: %d bytes through a %d byte ceiling needs a "+
			"pipeline that does not hold the payload five times over. Remove this skip with the "+
			"streaming change, not before", acceptanceFileBytes, acceptanceBudget)

		requireMemoryCap(t)
		w := stageCappedWorld(t, acceptanceBudget)
		// The compiled 256 MiB source ceiling would skip this fixture rather than ship it.
		raiseMaxFileBytes(t, w, acceptanceFileBytes*2)
		staged := stageIncompressibleFile(t, w, 0, acceptanceFileBytes)
		runUnderBudget(t, w, acceptanceScenario, resourceBudget{memory: acceptanceBudget}, 1, staged)
	})
}

// The interim guard measures per-file copies with a bounded fixture.
func smokeBigFile(t *testing.T) {
	t.Run("S3-big-file", func(t *testing.T) {
		requireMemoryCap(t)
		w := stageCappedWorld(t, bigFileBudget)
		staged := stageIncompressibleFile(t, w, 0, bigFileBytes)
		runUnderBudget(t, w, bigFileScenario, resourceBudget{memory: bigFileBudget}, 1, staged)
	})
}

// No cgroup or GOMEMLIMIT: either could mask whether admission serializes these files.
func smokeInFlightCap(t *testing.T) {
	t.Run("S4-in-flight-cap", func(t *testing.T) {
		w := stageWorld(t)
		w.gomaxprocs = smokeGOMAXPROCS
		w.extraEnv = append(w.extraEnv,
			fmt.Sprintf("%s=%d", envMaxInFlightBytes, inFlightCap))

		assertInFlightCapIsWired(t, w)

		staged := 0
		for i := range inFlightFiles {
			staged += stageIncompressibleFile(t, w, i, inFlightFileBytes)
		}
		t.Logf("%s: %d files of %d bytes under a %d byte in-flight cap, so no two can be "+
			"admitted together", inFlightScenario, inFlightFiles, inFlightFileBytes, inFlightCap)

		runUnderBudget(t, w, inFlightScenario, resourceBudget{memory: inFlightBudget}, inFlightFiles, staged)
	})
}

// A rejected non-numeric override proves the binary reads the cap this scenario sets.
func assertInFlightCapIsWired(t *testing.T, w *world) {
	t.Helper()
	// A copy, so the probe's deliberately broken value never reaches the measured run.
	probe := *w
	probe.extraEnv = append(slices.Clone(w.extraEnv), envMaxInFlightBytes+"=not-a-byte-count")

	obs := probe.observedSync(t)
	if obs.Err == nil {
		t.Fatalf("a sync with %s set to a non-number ended %s: the cap this scenario sets is not "+
			"being read, so the peak below would describe the compiled default instead\n%s",
			envMaxInFlightBytes, obs.exitStatus(), obs.Output)
	}
	if !strings.Contains(obs.Output, envMaxInFlightBytes) {
		t.Fatalf("a sync with %s set to a non-number ended %s without naming it:\n%s",
			envMaxInFlightBytes, obs.exitStatus(), obs.Output)
	}
}

// One large JSON string forces a whole decoded value; its CPU cost has no calibrated budget.
func smokeSingleLine(t *testing.T) {
	t.Run("S6-single-line-transcript", func(t *testing.T) {
		w := stageWorld(t)
		w.gomaxprocs = smokeGOMAXPROCS
		staged := stageSingleLineFile(t, w, singleLineFileBytes)
		runUnderBudget(t, w, singleLineScenario, resourceBudget{memory: singleLineBudget}, 1, staged)
	})
}

// Secrets add replacement and quoted-output copies, covered by singleLineDirtyBudget.
func smokeSingleLineSecrets(t *testing.T) {
	t.Run("S7-single-line-secret-transcript", func(t *testing.T) {
		w := stageWorld(t)
		w.gomaxprocs = smokeGOMAXPROCS
		staged, secrets := stageSingleLineSecretFile(t, w, singleLineFileBytes)
		runUnderBudget(t, w, singleLineSecretScenario,
			resourceBudget{memory: singleLineDirtyBudget}, 1, staged)

		assertRuleHits(t, w, corpusSessionID(0), map[string]int{"github-pat": secrets})
	})
}

// Zero leaves a dimension unmonitored.
type resourceBudget struct {
	memory int64 // bytes of peak RSS, gated on every run

	// The scenario judges its chosen repetition; gating each run would select the noisiest one.
	cpu float64
}

// Judge both resource cost and actual wire bytes; compressible fixtures could pass vacuously.
func runUnderBudget(t *testing.T, w *world, scenario string, budget resourceBudget, files, logical int) childObservation {
	t.Helper()

	var obs childObservation
	c := aroundStore(t, func() { obs = w.observedSync(t) })
	objects := len(w.currentKeys(t))

	t.Logf("%s: %d files, %d logical bytes, budget %d: %s in %v, peak %d bytes (%s), "+
		"%.2f cpu seconds, %d up and %d down (%.3f wire ratio), %d S3 requests, %d objects",
		scenario, files, logical, budget.memory, obs.exitStatus(), obs.Elapsed.Round(time.Millisecond),
		obs.PeakRSS, obs.PeakRSSSource, obs.CPUSeconds, c.up, c.down,
		float64(c.up+c.down)/float64(logical), c.requests, objects)

	// Recorded before anything is judged: a breach with no row is one nobody can calibrate against.
	recordResult(t, perfResult{
		Scenario:        scenario,
		CorpusFiles:     files,
		CorpusBytes:     logical,
		ChildGOMAXPROCS: w.gomaxprocs,
		// Record shaping even when the scenario does not judge latency.
		ShapedRTTMillis:   smokeRTT.Milliseconds(),
		RepSeconds:        []float64{obs.Elapsed.Seconds()},
		BestSeconds:       obs.Elapsed.Seconds(),
		ProxiedBytesUp:    c.up,
		ProxiedBytesDown:  c.down,
		S3Requests:        c.requests,
		Objects:           objects,
		PeakRSSBytes:      obs.PeakRSS,
		PeakRSSSource:     obs.PeakRSSSource,
		MemoryBudgetBytes: budget.memory,
		CPUSeconds:        obs.CPUSeconds,
		CPUBudgetSeconds:  budget.cpu,
		ExitStatus:        obs.exitStatus(),
	})

	// The timeout first: both arrive as a SIGKILL and only one of them is about memory.
	if obs.TimedOut {
		t.Fatalf("%s: the sync did not finish inside %v and was killed for running long, not by "+
			"its %d byte cap; peak read %d bytes (%s)",
			scenario, syncTimeout, budget.memory, obs.PeakRSS, obs.PeakRSSSource)
	}
	// Not necessarily this scenario's ceiling: S4 runs uncapped, so a kill there came from the machine.
	if obs.Killed() {
		t.Fatalf("%s: the child was killed carrying %d bytes of fixture in %d files under a %d "+
			"byte budget; peak read %d bytes (%s) before it went",
			scenario, logical, files, budget.memory, obs.PeakRSS, obs.PeakRSSSource)
	}
	if obs.Err != nil {
		t.Fatalf("%s: quesma-shipper run --once ended %s: %v\n%s", scenario, obs.exitStatus(), obs.Err, obs.Output)
	}

	counts := summary(t, obs.Output)
	if counts["shipped"] < files {
		t.Errorf("%s: the run shipped %d of %d files:\n%s", scenario, counts["shipped"], files, obs.Output)
	}
	if counts["failed"] != 0 {
		t.Errorf("%s: the run failed %d files:\n%s", scenario, counts["failed"], obs.Output)
	}
	if want := files + smokeSidecarObjects; objects != want {
		t.Errorf("%s: %d objects under %s, want exactly %d (%d files and %d sidecars)",
			scenario, objects, w.keyRoot, want, files, smokeSidecarObjects)
	}
	if floor := int64(logical) / 2; c.up < floor {
		t.Errorf("%s: %d bytes went up for %d logical bytes, under the %d floor: the fixture "+
			"compressed away and the run proves nothing about carrying %d bytes",
			scenario, c.up, logical, floor, logical)
	}

	assertPeakUnderBudget(t, scenario, obs, budget.memory)
	assertNoResidualScratch(t, w)
	return obs
}

func raiseMaxFileBytes(t *testing.T, w *world, limit int64) {
	t.Helper()
	path := filepath.Join(w.Config, "trajectory-shipper", "config.yaml")
	body, err := os.ReadFile(path)
	require.Falsef(t, err != nil, "read the world's config: %v", err)
	body = append(body, fmt.Sprintf(
		"sources:\n  - id: claude-code-transcripts\n    max_file_bytes: %d\n", limit)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("raise max_file_bytes to %d: %v", limit, err)
	}
}
