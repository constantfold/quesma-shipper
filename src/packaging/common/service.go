// Shared service lifecycle for per-user agents: platform packages own the actual supervisor,
// common owns the input contract and the reported status.
package common

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Kind is the supervision mechanism in use on this host.
type Kind string

const (
	KindLaunchd     Kind = "launchd"
	KindSystemd     Kind = "systemd-user"
	KindWindowsTask Kind = "windows-task"
	// KindCron is the non-systemd Linux fallback: the client prints a crontab line, never edits one.
	KindCron Kind = "cron"
	// KindUnsupported means no supervision here; `quesma-shipper run` still works in the foreground.
	KindUnsupported Kind = "unsupported"
)

// Spec is what to install.
type Spec struct {
	// Executable is the absolute path to the binary; a relative path or a moving symlink breaks.
	Executable string
	// Args is the verb the agent runs: `run`, so the flock and the schedule live in one process.
	Args []string
	// Home and StateDir go into the agent's environment; launchd hands an agent almost none.
	Home     string
	StateDir string
	// LogDir is where stdout/stderr go; discarded output makes "it never runs" undiagnosable.
	LogDir string
	// Tick matters only to the cron fallback, which IS the ticker; zero means 15 minutes.
	Tick time.Duration
	// StopTimeout must outlast the drain deadline: a drain killed after SIGTERM looks clean.
	StopTimeout time.Duration
}

// ServiceSpecFor describes an agent run from exe.
func ServiceSpecFor(exe, stateDir string, stopTimeout, tick time.Duration) (Spec, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Spec{}, err
	}
	return Spec{Executable: exe, Args: []string{"run"}, Home: home,
		StateDir: stateDir, LogDir: filepath.Join(stateDir, "logs"), StopTimeout: stopTimeout,
		Tick: tick}, nil
}

// EntryMode keeps the per-user service entry private.
const EntryMode = 0o600

// ExitTimeout is the kill window shared by service renderers and shutdown logic.
func ExitTimeout(spec Spec) time.Duration {
	if spec.StopTimeout <= 0 {
		return 5*time.Minute + 30*time.Second
	}
	return spec.StopTimeout + 30*time.Second
}

// Status is what `status` and `doctor` report.
type Status struct {
	Kind Kind
	// Installed means the unit or plist file exists on disk.
	Installed bool
	// Loaded means the supervisor picked it up; written-but-never-loaded is the common failure.
	Loaded bool
	// Path is the unit or plist file.
	Path string
	// Program is set by supervisors whose entries are not represented by a readable file.
	Program string
	// LastRun is when the loop last completed a flush; zero on a loaded agent is the alarm.
	LastRun time.Time
	// Detail explains the state in a sentence, including whatever the supervisor said.
	Detail string
}

// ValidateInstall checks the invariants shared by every platform service installer.
func ValidateInstall(spec Spec) error {
	if os.Geteuid() == 0 {
		return errors.New("supervise: refusing to install as root: this is a per-user agent, " +
			"and running as root would resolve ~ to root's home and read the wrong user's files")
	}
	if spec.Executable == "" {
		return errors.New("supervise: no executable path")
	}
	if !filepath.IsAbs(spec.Executable) {
		return fmt.Errorf("supervise: %q is not an absolute path: a relative path in a "+
			"supervision entry breaks as soon as the agent's working directory differs", spec.Executable)
	}
	return nil
}

// ErrCronManual signals that the caller must print the hint rather than claim an install.
var ErrCronManual = errors.New("supervise: this host has no systemd --user; " +
	"add the printed crontab line yourself")

// ErrTaskDeleteUnverified marks an unconfirmed Windows task delete; it must not block removal.
var ErrTaskDeleteUnverified = errors.New("supervise: delete scheduled task, outcome unverified")

// CronHint is the non-systemd fallback, a line the operator adds manually.
func CronHint(spec Spec) string {
	return fmt.Sprintf("%s %s run --once >> %s 2>&1",
		cronExpr(spec.Tick), spec.Executable, filepath.Join(spec.LogDir, "cron.log"))
}

func cronExpr(tick time.Duration) string {
	switch {
	case tick <= 0:
		return "*/15 * * * *"
	case tick <= time.Minute:
		return "* * * * *"
	case tick < time.Hour:
		return fmt.Sprintf("*/%d * * * *", int((tick+time.Minute-1)/time.Minute))
	case tick < 24*time.Hour:
		return fmt.Sprintf("0 */%d * * *", int((tick+time.Hour-1)/time.Hour))
	default:
		return "0 0 * * *"
	}
}

// ServiceProgram reads the executable owned by an installed service entry.
func ServiceProgram(st Status) string {
	if st.Program != "" {
		return st.Program
	}
	raw, err := os.ReadFile(st.Path)
	if err != nil {
		return ""
	}
	text := string(raw)
	if _, after, ok := strings.Cut(text, "<key>ProgramArguments</key>"); ok {
		if _, after, ok = strings.Cut(after, "<string>"); ok {
			program, _, _ := strings.Cut(after, "</string>")
			var decoded string
			if xml.Unmarshal([]byte("<string>"+program+"</string>"), &decoded) == nil {
				return decoded
			}
			return ""
		}
	}
	if _, after, ok := strings.Cut(text, "\nExecStart="); ok {
		line, _, _ := strings.Cut(after, "\n")
		program := strings.TrimPrefix(strings.Fields(line)[0], "\"")
		return strings.TrimSuffix(program, "\"")
	}
	return ""
}

// XMLText escapes s for the XML service entries: the LaunchAgent plist and the Task Scheduler task.
func XMLText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// CurrentExecutable is this binary's real path, behind any package-installed symlink.
func CurrentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine this binary's path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}
