//go:build perf

// What a child run cost, and what it left behind. The shipper runs as an ordinary child, so peak
// memory, CPU and exit status are three syscalls away. Peak memory is read two ways (VmHWM cannot
// undercount but misses the last moments; Maxrss arrives only after exit) and the larger is checked.
package perf

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Not a sampling rate: VmHWM only ever grows, so this decides how likely a read lands before exit.
const vmHWMInterval = 20 * time.Millisecond

// Without it Wait blocks on the pipe copy: cancelling kills only the direct child, sudo for a capped run.
const waitDelay = 30 * time.Second

// One run of the shipper, measured rather than judged; nothing here fails a test.
type childObservation struct {
	Output  string
	Elapsed time.Duration

	PeakRSS       int64  // the larger of the two readings
	PeakRSSSource string // which one it was
	CPUSeconds    float64
	ExitCode      int
	Signal        syscall.Signal
	TimedOut      bool  // separates a syncTimeout kill from the SIGKILL a scenario expected
	Err           error // what Wait returned
}

// The one-word form that goes into the results file.
func (o childObservation) exitStatus() string {
	switch {
	case o.Signal != 0:
		return "signal " + o.Signal.String()
	case o.ExitCode == 0:
		return "ok"
	default:
		return fmt.Sprintf("exit %d", o.ExitCode)
	}
}

// Two shapes, because a wrapper reports its child's death the way a shell does, as 128 plus the
// signal. A syncTimeout kill looks identical from here, so a scenario reads TimedOut first.
func (o childObservation) Killed() bool {
	return o.Signal == syscall.SIGKILL || o.ExitCode == 128+int(syscall.SIGKILL)
}

// The wall clock covers the whole process, startup included, or it would flatter every steady state.
func (w *world) observedSync(t *testing.T) childObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
	defer cancel()

	argv := append(slices.Clone(w.launcher), w.binary, "run", "--once")
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = w.childEnv()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = waitDelay

	start := time.Now()
	require.NoError(t, cmd.Start(), "start the shipper")
	peak := watchPeakRSS(cmd.Process.Pid)
	err := cmd.Wait()
	vmHWM := peak()
	obs := childObservation{Output: out.String(), Elapsed: time.Since(start), TimedOut: ctx.Err() != nil, Err: err}

	st := cmd.ProcessState
	require.Falsef(t, st == nil, "the shipper left no process state behind: %v", err)
	obs.ExitCode = st.ExitCode()
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		obs.Signal = ws.Signal()
	}
	ru, ok := st.SysUsage().(*syscall.Rusage)
	require.Truef(t, ok, "no rusage for the child on %s: peak memory cannot be observed", runtime.GOOS)
	seconds := func(tv syscall.Timeval) float64 { return float64(tv.Sec) + float64(tv.Usec)/1e6 }
	obs.CPUSeconds = seconds(ru.Utime) + seconds(ru.Stime)

	// Maxrss is kilobytes on Linux, bytes on darwin; a loud stop elsewhere rather than a peak off by 1000x.
	var unit int64
	switch runtime.GOOS {
	case "linux":
		unit = 1 << 10
	case "darwin":
		unit = 1
	default:
		t.Fatalf("the unit of Rusage.Maxrss on %s is not known here", runtime.GOOS)
	}
	obs.PeakRSS, obs.PeakRSSSource = ru.Maxrss*unit, "Maxrss"
	if vmHWM > obs.PeakRSS {
		obs.PeakRSS, obs.PeakRSSSource = vmHWM, "VmHWM"
	}
	return obs
}

// The returned function, called once after Wait, stops the watch: a reaped pid's numbers belong to
// someone else. Zero where /proc is not.
func watchPeakRSS(pid int) func() int64 {
	if runtime.GOOS != "linux" {
		return func() int64 { return 0 }
	}
	done := make(chan struct{})
	result := make(chan int64, 1)
	go func() {
		var peak int64
		tick := time.NewTicker(vmHWMInterval)
		defer tick.Stop()
		for {
			peak = max(peak, peakVmHWM(pid))
			select {
			case <-done:
				result <- peak
				return
			case <-tick.C:
			}
		}
	}()
	return func() int64 {
		close(done)
		return <-result
	}
}

// The subtree, since a capped run has wrappers above the shipper; zero once the process is gone.
func peakVmHWM(pid int) int64 {
	var peak int64
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
				if fields := strings.Fields(rest); len(fields) > 0 {
					if kb, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
						peak = kb << 10
					}
				}
				break
			}
		}
	}
	tasks := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, _ := os.ReadDir(tasks)
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(tasks, e.Name(), "children"))
		if err != nil {
			continue
		}
		for _, field := range strings.Fields(string(raw)) {
			if child, err := strconv.Atoi(field); err == nil {
				peak = max(peak, peakVmHWM(child))
			}
		}
	}
	return peak
}

// Touching the budget is a failure. Enforced only on Linux, where VmHWM does not depend on when the
// harness looked; elsewhere the log says the check did not run.
func assertPeakUnderBudget(t *testing.T, scenario string, obs childObservation, budget int64) {
	t.Helper()
	require.Falsef(t, budget <= 0, "%s declared a memory budget of %d bytes; a budget is a positive number of bytes", scenario, budget)
	switch {
	case obs.PeakRSS <= 0:
		t.Errorf("%s: peak RSS read as %d bytes from %s: the instrument is what this check would "+
			"be passing, not the run", scenario, obs.PeakRSS, obs.PeakRSSSource)
	case runtime.GOOS != "linux":
		t.Logf("%s: peak %d bytes (%s) against a %d byte budget, recorded only: "+
			"the memory check needs VmHWM and %s has no /proc",
			scenario, obs.PeakRSS, obs.PeakRSSSource, budget, runtime.GOOS)
	case obs.PeakRSS >= budget:
		t.Errorf("%s: peak RSS %d bytes (%s) reached its %d byte budget",
			scenario, obs.PeakRSS, obs.PeakRSSSource, budget)
	default:
		t.Logf("%s: peak RSS %d bytes (%s), %d bytes under the %d byte budget",
			scenario, obs.PeakRSS, obs.PeakRSSSource, budget-obs.PeakRSS, budget)
	}
}

// A zero budget makes no CPU claim. This runs on every platform, so it must hold on the slowest one.
func assertCPUUnderBudget(t *testing.T, scenario string, obs childObservation, budget float64) {
	t.Helper()
	switch {
	case budget <= 0:
	case obs.CPUSeconds <= 0:
		t.Errorf("%s: child CPU read as %.3f seconds: the instrument is what this check would "+
			"be passing, not the run", scenario, obs.CPUSeconds)
	case obs.CPUSeconds >= budget:
		t.Errorf("%s: the child burned %.2f CPU seconds, reaching its %.2f second budget",
			scenario, obs.CPUSeconds, budget)
	default:
		t.Logf("%s: %.2f CPU seconds, %.2f under the %.2f second budget",
			scenario, obs.CPUSeconds, budget-obs.CPUSeconds, budget)
	}
}

// Every durable local write is temp-then-rename, so a leftover temp file is a write that never committed.
func assertNoResidualScratch(t *testing.T, w *world) {
	t.Helper()
	var leftover []string
	for _, root := range []string{w.State, w.Config, w.Home} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if !d.IsDir() && (strings.Contains(name, ".tmp-") || strings.HasSuffix(name, ".tmp") ||
				strings.HasSuffix(name, ".part") || strings.HasSuffix(name, ".partial")) {
				leftover = append(leftover, path)
			}
			return nil
		})
		require.NoErrorf(t, err, "walk %s for scratch files", root)
	}
	if len(leftover) > 0 {
		slices.Sort(leftover)
		shown := leftover[:min(10, len(leftover))]
		t.Errorf("a drained sync left %d scratch files behind, first %d: %s",
			len(leftover), len(shown), strings.Join(shown, " "))
	}
}

// Deliberately loose: this proves the check reads a real number, not that the run is small.
const selfTestMemoryBudget = 512 << 20

// The instruments, checked against one cheap sync: the scenarios that rely on them cost minutes each.
func TestTheHarnessObservesAChildRun(t *testing.T) {
	w := stageWorld(t)
	files := smallCorpusFiles
	stageCorpusFiles(t, w, files)

	var obs childObservation
	c := aroundStore(t, func() { obs = w.mustSync(t) })

	if got := summary(t, obs.Output)["shipped"]; got < files {
		t.Fatalf("the self-test run shipped %d of %d files", got, files)
	}
	objects := len(w.currentKeys(t))

	assert.Falsef(t, c.up <= 0 || c.down <= 0, "the run shipped %d files and the proxy counted %d bytes up, %d down", files, c.up, c.down)
	assert.Falsef(t, c.requests <= 0, "the run shipped %d files and MinIO counted %d new S3 requests", files, c.requests)
	assert.GreaterOrEqualf(t, objects, files, "the run shipped %d files and left %d objects under %s", files, objects, w.keyRoot)
	assert.Falsef(t, obs.PeakRSS <= 0, "the child's peak RSS read as %d bytes from %s", obs.PeakRSS, obs.PeakRSSSource)
	assert.Falsef(t, obs.CPUSeconds <= 0, "the child's CPU time read as %v seconds", obs.CPUSeconds)

	assertPeakUnderBudget(t, selfTestScenario, obs, selfTestMemoryBudget)
	assertNoResidualScratch(t, w)

	recordResult(t, perfResult{
		Scenario:          selfTestScenario,
		CorpusFiles:       files,
		ChildGOMAXPROCS:   w.gomaxprocs,
		RepSeconds:        []float64{obs.Elapsed.Seconds()},
		BestSeconds:       obs.Elapsed.Seconds(),
		ProxiedBytesUp:    c.up,
		ProxiedBytesDown:  c.down,
		S3Requests:        c.requests,
		Objects:           objects,
		PeakRSSBytes:      obs.PeakRSS,
		PeakRSSSource:     obs.PeakRSSSource,
		MemoryBudgetBytes: selfTestMemoryBudget,
		CPUSeconds:        obs.CPUSeconds,
		ExitStatus:        obs.exitStatus(),
	})
}
