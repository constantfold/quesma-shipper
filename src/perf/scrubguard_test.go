//go:build perf

// The scrub guard: what a sync burns in CPU, of which scrubbing is the largest term, end to end in
// the shipped binary. CPU seconds, not wall clock: CPU excludes the waiting where runner noise lives.
package perf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Big enough that scrubbing dominates the CPU; the same size as the memory guard's fixture.
const scrubGuardBytes int64 = 32 << 20

// Every other 8 KiB line, so one run exercises both the verification path and the prefilter's fast path.
const scrubGuardSecretEveryLines = 2

// Cold repetitions the CPU minimum is taken over.
const scrubGuardReps = 3

// PROVISIONAL, and 1.3x the observed ceiling only because the CPU figure is a minimum of cold runs and
// the memory one is measured for this uncapped scenario. Loosening either to pass is not an option.
const (
	scrubGuardCPUBudget       = 0.95      // seconds: 1.3x the 0.699 s runner ceiling
	scrubGuardBudget    int64 = 272 << 20 // bytes: 1.3x the 218 MB worst
)

// No cgroup and no GOMEMLIMIT: a soft limit buys collector CPU, the number read here, and a capped
// run's rusage would describe the sudo and systemd-run wrappers.
func smokeScrubGuard(t *testing.T) {
	t.Run("S5-scrub-cpu-guard", func(t *testing.T) {
		w := stageSmokeWorld(t)

		staged, secrets := stageIncompressibleFile(t, w, 0, scrubGuardBytes, scrubGuardSecretEveryLines)
		t.Logf("%s: %d logical bytes carrying %d planted secret pairs, one per %d bytes of fill",
			scrubGuardScenario, staged, secrets, scrubGuardSecretEveryLines*memguardLineFill)

		// CPU is judged on the minimum, since interference only ever adds; memory on every repetition.
		var best childObservation
		reps := make([]time.Duration, 0, scrubGuardReps)
		for rep := range scrubGuardReps {
			if rep > 0 {
				w.reset(t)
			}
			obs := runUnderBudget(t, w, scrubGuardScenario,
				resourceBudget{memory: scrubGuardBudget, cpu: scrubGuardCPUBudget}, 1, staged)
			reps = append(reps, time.Duration(obs.CPUSeconds*float64(time.Second)))
			if rep == 0 || obs.CPUSeconds < best.CPUSeconds {
				best = obs
			}
		}
		t.Logf("%s: cpu across %d cold repetitions: %s, judging the minimum",
			scrubGuardScenario, scrubGuardReps, durationList(reps))
		assertCPUUnderBudget(t, scrubGuardScenario, best, scrubGuardCPUBudget)

		assertRuleHits(t, w, corpusSessionID(0), map[string]int{
			"github-pat":        secrets,
			"aws-access-key-id": secrets,
			// A filler run past the entropy floor would be redacted wholesale.
			"generic-entropy": 0,
		})
	})
}

// Scoped to the shipped entries for this transcript, since a sync also scrubs derived objects.
func assertRuleHits(t *testing.T, w *world, session string, want map[string]int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(w.State, "trajectory-shipper", "audit.log"))
	require.NoError(t, err)
	got := map[string]int{}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Decision string         `json:"decision"`
			File     string         `json:"file"`
			RuleHits map[string]int `json:"rule_hits"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit log line is not JSON: %v", err)
		}
		if entry.Decision != "shipped" || !strings.HasSuffix(entry.File, session+".jsonl") {
			continue
		}
		found = true
		for rule, n := range entry.RuleHits {
			got[rule] += n
		}
	}
	require.Falsef(t, !found, "no shipped audit entry for %s.jsonl: the ledger this gate reads is not the run's", session)
	for rule, n := range want {
		assert.Falsef(t, got[rule] != n, "rule %q recorded %d hits, want %d (whole ledger for this file: %v)", rule, got[rule], n, got)
	}
}
