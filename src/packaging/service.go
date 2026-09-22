package packaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

type ServiceStatus = common.Status

func ServiceState(stateDir string) ServiceStatus {
	return ServiceStateContext(context.Background(), stateDir)
}

func ServiceStateContext(ctx context.Context, stateDir string) ServiceStatus {
	st := serviceState(ctx)
	st.LastRun = lastRun(stateDir)
	return st
}

const (
	runMarker         = "last_run"
	selfUpdateHopName = "selfupdate_hop"
)

// RecordRun stamps the marker after every flush, including one that shipped nothing: the
// fingerprint document only advances on collection, so it cannot show a quiet install is alive.
func RecordRun(stateDir string, at time.Time) error {
	return platform.WriteAtomic(filepath.Join(stateDir, runMarker), []byte(at.UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// lastRun reads the marker; zero means never, and a corrupt marker reads as never.
func lastRun(stateDir string) time.Time {
	raw, _, err := platform.ReadWhole(filepath.Join(stateDir, runMarker), 128)
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	return t
}

// RotateLogs bounds a crash loop appending the same stack: it moves an oversized agent log aside at
// startup, which works because the supervisor reopens the path per launch.
func RotateLogs(logDir string) {
	if logDir == "" {
		return
	}
	for _, name := range []string{"agent.out.log", "agent.err.log"} {
		platform.RotateLog(filepath.Join(logDir, name))
	}
}

func ReadSelfUpdateHop(stateDir string) string {
	raw, _, err := platform.ReadWhole(filepath.Join(stateDir, selfUpdateHopName), 256)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func WriteSelfUpdateHop(stateDir, version string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return platform.WriteAtomic(filepath.Join(stateDir, selfUpdateHopName), []byte(version+"\n"), 0o600)
}

func ClearSelfUpdateHop(stateDir string) error {
	if err := os.Remove(filepath.Join(stateDir, selfUpdateHopName)); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func ServiceProgram(st ServiceStatus) string { return common.ServiceProgram(st) }
func RemoveState(stateDir string) error      { return os.RemoveAll(stateDir) }

// SameProgram compares executable paths the way the host's filesystem does.
func SameProgram(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return a == b
}

// ProgramRemovalDeferred: Windows cannot delete a running executable, so its uninstaller finishes later.
func ProgramRemovalDeferred() bool { return runtime.GOOS == "windows" }

func RemovalUnverified(err error) bool { return errors.Is(err, common.ErrTaskDeleteUnverified) }

// RestartBudget is how long a restart may legitimately take: the agent ships a final slice
// under drainDeadline before it exits, and the supervisor kills it only after that window.
func RestartBudget(drainDeadline time.Duration) time.Duration {
	return common.ExitTimeout(common.Spec{StopTimeout: drainDeadline})
}
