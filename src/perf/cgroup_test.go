//go:build perf

// Linux memory-cap enforcement and the subprocess that proves it kills an over-budget run.
package perf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The runtime gets three quarters of the kernel cap, giving GC a chance before SIGKILL.
const memoryLimitNumerator, memoryLimitDenominator = 3, 4

// Leave headroom above the test budget so ordinary breaches produce a measured failure.
const memoryCapHeadroom = 2

// Snapshot the environment after setting GOMEMLIMIT; sudo will not inherit later changes.
func stageCappedWorld(t *testing.T, budget int64) *world {
	t.Helper()
	w := stageWorld(t)
	w.gomaxprocs = smokeGOMAXPROCS
	hard := budget * memoryCapHeadroom
	w.extraEnv = append(w.extraEnv,
		fmt.Sprintf("GOMEMLIMIT=%d", hard*memoryLimitNumerator/memoryLimitDenominator))
	w.launcher = memoryCapArgs(hard, w.childVars())
	return w
}

// The memory controller must exist before systemd-run can enforce a cap.
const cgroupControllers = "/sys/fs/cgroup/cgroup.controllers"

// Above runtime startup cost, but cheap enough for the bounded hog probe.
const memoryCapProbeBytes int64 = 128 << 20

// Bound the hog even when the host accepts a cap without enforcing it.
const memoryHogOvershoot = 4

// An allocation probe still running after two minutes is stuck.
const memoryCapProbeTimeout = 2 * time.Minute

const ciEnv = "GITHUB_ACTIONS"

var (
	capOnce sync.Once
	capErr  error
)

// A missing cap fails CI; unsupported developer machines skip explicitly.
func requireMemoryCap(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("the memory cap is a cgroup and %s has none: this scenario needs Linux", runtime.GOOS)
	}
	capOnce.Do(func() { capErr = probeMemoryCap() })
	if capErr == nil {
		return
	}
	if os.Getenv(ciEnv) == "true" {
		t.Fatalf("no enforceable memory cap on this CI runner, where it is a precondition "+
			"rather than an option: %v", capErr)
	}
	t.Skipf("no enforceable memory cap on this machine: %v", capErr)
}

// Verify the controller, launcher, child uid and actual OOM enforcement.
func probeMemoryCap() error {
	controllers, err := os.ReadFile(cgroupControllers)
	if err != nil {
		return fmt.Errorf("no cgroup v2 at %s: %v", cgroupControllers, err)
	}
	if !slices.Contains(strings.Fields(string(controllers)), "memory") {
		return fmt.Errorf("%s offers no memory controller, only %q",
			cgroupControllers, strings.TrimSpace(string(controllers)))
	}
	for _, tool := range []string{"sudo", "systemd-run"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("no %s on this machine: %v", tool, err)
		}
	}
	id, err := exec.LookPath("id")
	if err != nil {
		return fmt.Errorf("no id(1) to probe the wrapper with: %v", err)
	}

	argv := append(memoryCapArgs(memoryCapProbeBytes, nil), id, "-u")
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	// The last line: sudo and systemd-run write their own noise to stderr.
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return fmt.Errorf("%s printed nothing", strings.Join(argv, " "))
	}
	if got, want := fields[len(fields)-1], strconv.Itoa(os.Getuid()); got != want {
		return fmt.Errorf("a capped child ran as uid %s, not %s: it would leave a world this "+
			"test cannot clean up", got, want)
	}
	return probeMemoryCapKills()
}

// Run this test binary as a bounded hog to prove the kernel enforces its accepted cap.
func probeMemoryCapKills() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("no path to this test binary to run a hog with: %v", err)
	}
	want := memoryCapProbeBytes * memoryHogOvershoot

	ctx, cancel := context.WithTimeout(context.Background(), memoryCapProbeTimeout)
	defer cancel()
	argv := append(memoryCapArgs(memoryCapProbeBytes, []string{fmt.Sprintf("%s=%d", memoryHogEnv, want)}), self)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()

	if err == nil {
		return fmt.Errorf("a child that touched %d bytes under a %d byte cap exited cleanly: "+
			"the cap is accepted and not enforced, so nothing below it would be capped either",
			want, memoryCapProbeBytes)
	}
	st := cmd.ProcessState
	if st == nil {
		return fmt.Errorf("the hog left no process state behind: %v: %s",
			err, strings.TrimSpace(string(out)))
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	killed := (ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL) ||
		st.ExitCode() == 128+int(syscall.SIGKILL)
	if !killed {
		return fmt.Errorf("a child that touched %d bytes under a %d byte cap ended %v rather "+
			"than being killed: %s", want, memoryCapProbeBytes, err, strings.TrimSpace(string(out)))
	}
	return nil
}

const memoryHogEnv = "SHIPPER_PERF_MEMORY_HOG_BYTES"

// Touch every page: untouched address space does not count toward the cgroup cap.
func runMemoryHog(spec string) int {
	want, err := strconv.ParseInt(strings.TrimSpace(spec), 10, 64)
	if err != nil || want <= 0 {
		fmt.Fprintf(os.Stderr, "perf: %s=%q is not a positive whole number of bytes\n",
			memoryHogEnv, spec)
		return 2
	}
	const (
		chunk = 1 << 20
		page  = 4 << 10
	)
	held := make([][]byte, 0, want/chunk+1)
	for total := int64(0); total < want; total += chunk {
		buf := make([]byte, chunk)
		for i := 0; i < len(buf); i += page {
			buf[i] = 1
		}
		held = append(held, buf)
	}
	// Held to the end: memory the collector could take back is not something a cap has to kill.
	runtime.KeepAlive(held)
	return 0
}

// Keep the child a descendant, forbid swap thrashing, and pass environment through sudo explicitly.
func memoryCapArgs(limit int64, vars []string) []string {
	argv := []string{
		"sudo", "-n",
		"systemd-run", "--scope", "--quiet",
		fmt.Sprintf("--uid=%d", os.Getuid()),
		fmt.Sprintf("--gid=%d", os.Getgid()),
		fmt.Sprintf("--property=MemoryMax=%d", limit),
		"--property=MemorySwapMax=0",
		"--property=OOMPolicy=kill",
	}
	for _, v := range vars {
		argv = append(argv, "--setenv="+v)
	}
	return append(argv, "--")
}
