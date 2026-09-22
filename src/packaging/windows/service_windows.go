//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/QuesmaOrg/quesma-shipper/packaging/common"
)

func InstallService(spec Spec) error {
	if err := common.ValidateInstall(spec); err != nil {
		return err
	}
	if _, err := os.Stat(taskRunner(spec.Executable)); err != nil {
		return fmt.Errorf("supervise: task runner beside installed program: %w", err)
	}
	current, err := currentUser()
	if err != nil {
		return err
	}
	if err := verifyInstallDir(filepath.Dir(spec.Executable), current.Uid); err != nil {
		return err
	}
	// Retired first, or both tasks would be live and the second would never take the state lock.
	if err := retireLegacyTask(current.Uid); err != nil {
		return err
	}
	name := taskName(current.Uid)

	f, err := os.CreateTemp("", "quesma-shipper-task-*.xml")
	if err != nil {
		return fmt.Errorf("supervise: create task definition: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.Write(taskXMLForSchtasks(renderTask(spec, current.Uid, current.Username))); err != nil {
		f.Close()
		return fmt.Errorf("supervise: write task definition: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("supervise: close task definition: %w", err)
	}

	// /F is an overwrite of this user's own task now that the name carries their SID.
	if out, err := schtasks("/Create", "/TN", name, "/XML", path, "/F"); err != nil {
		return fmt.Errorf("supervise: register scheduled task: %s", commandError(err, out))
	}
	if out, err := schtasks("/Run", "/TN", name); err != nil {
		return fmt.Errorf("supervise: start scheduled task: %s", commandError(err, out))
	}
	return nil
}

func UninstallService() error {
	current, err := currentUser()
	if err != nil {
		return err
	}
	name := taskName(current.Uid)
	// An install that predates per-user names is removed too, or uninstalling would leave it live.
	legacyErr := retireLegacyTask(current.Uid)

	_, _ = schtasks("/End", "/TN", name)
	out, err := schtasks("/Delete", "/TN", name, "/F")
	if err == nil {
		return legacyErr
	}
	exists, verifyErr := taskExists(context.Background(), name)
	if verifyErr == nil && !exists {
		return legacyErr
	}
	if verifyErr != nil {
		return fmt.Errorf("%w: %s (could not verify absence: %v)",
			common.ErrTaskDeleteUnverified, commandError(err, out), verifyErr)
	}
	return fmt.Errorf("supervise: delete scheduled task: %s", commandError(err, out))
}

// ownLegacyTask reads the pre-rename task if this user owns it; unreadable means absent or another user's.
func ownLegacyTask(ctx context.Context, userSID string) ([]byte, bool) {
	out, err := schtasksContext(ctx, "/Query", "/TN", legacyTaskName, "/XML")
	if err != nil {
		return nil, false
	}
	doc, err := parseTask(out)
	return out, err == nil && legacyTaskIsOurs(doc, userSID)
}

func retireLegacyTask(userSID string) error {
	if _, ours := ownLegacyTask(context.Background(), userSID); !ours {
		return nil
	}
	_, _ = schtasks("/End", "/TN", legacyTaskName)
	if out, err := schtasks("/Delete", "/TN", legacyTaskName, "/F"); err != nil {
		return fmt.Errorf("supervise: retire the former scheduled task %q: %s", legacyTaskName, commandError(err, out))
	}
	return nil
}

func currentUser() (*user.User, error) {
	current, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("supervise: current Windows user: %w", err)
	}
	if !strings.HasPrefix(current.Uid, "S-") {
		return nil, fmt.Errorf("supervise: current Windows user has invalid SID %q", current.Uid)
	}
	return current, nil
}

// queryOwnTask falls back to this user's pre-rename task, and returns the per-user name even when nothing is registered.
func queryOwnTask(ctx context.Context, userSID string) (string, []byte, error) {
	name := taskName(userSID)
	out, err := schtasksContext(ctx, "/Query", "/TN", name, "/XML")
	if err == nil {
		return name, out, nil
	}
	if legacyOut, ours := ownLegacyTask(ctx, userSID); ours {
		return legacyTaskName, legacyOut, nil
	}
	return name, out, err
}

func ServiceState(ctx context.Context) Status {
	current, err := currentUser()
	if err != nil {
		return Status{Kind: common.KindWindowsTask, Detail: err.Error()}
	}
	name, out, err := queryOwnTask(ctx, current.Uid)
	st := Status{Kind: common.KindWindowsTask, Path: name}
	if err != nil {
		exists, verifyErr := taskExists(ctx, name)
		switch {
		case verifyErr == nil && !exists:
			st.Detail = "no scheduled task installed; `quesma-shipper run` works in the foreground"
		case verifyErr != nil:
			st.Detail = "cannot query scheduled task: " + commandError(err, out) + "; cannot enumerate tasks: " + verifyErr.Error()
		default:
			st.Installed = true
			st.Detail = "cannot query scheduled task: " + commandError(err, out)
		}
		return st
	}
	st.Installed = true
	doc, err := parseTask(out)
	if err != nil {
		st.Detail = "scheduled task exists but its definition cannot be read: " + err.Error()
		return st
	}
	st.Loaded = doc.enabled()
	st.Program = programFromTask(doc.Command)
	if st.Loaded {
		st.Detail = "registered and enabled at user logon"
	} else {
		st.Detail = "scheduled task is disabled: re-run the Quesma Shipper installer"
	}
	return st
}

func RestartService(ctx context.Context) error {
	current, err := currentUser()
	if err != nil {
		return err
	}
	name, _, _ := queryOwnTask(ctx, current.Uid)
	_, _ = schtasksContext(ctx, "/End", "/TN", name)
	out, err := schtasksContext(ctx, "/Run", "/TN", name)
	if err != nil {
		return fmt.Errorf("restart scheduled task: %s", commandError(err, out))
	}
	return nil
}

// RestartCommand is a hint printed for the user; the caller drops it when it is empty.
func RestartCommand() string {
	current, err := currentUser()
	if err != nil {
		return ""
	}
	name, _, _ := queryOwnTask(context.Background(), current.Uid)
	return `schtasks /Run /TN "` + name + `"`
}

func RemoveProgram(executable string) (string, error) {
	uninstaller := filepath.Join(filepath.Dir(executable), "unins000.exe")
	if _, err := os.Stat(uninstaller); err == nil {
		cmd := exec.Command(uninstaller, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
		if err := cmd.Start(); err != nil {
			return uninstaller, fmt.Errorf("start Windows uninstaller: %w", err)
		}
		return uninstaller, nil
	}
	return executable, errors.New("this is a portable executable; remove it after this command exits")
}

func schtasks(args ...string) ([]byte, error) {
	return exec.Command("schtasks.exe", args...).CombinedOutput()
}

func schtasksContext(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "schtasks.exe", args...).CombinedOutput()
}

// schtasksStdout keeps listings clear of the warnings schtasks writes to stderr for tasks it cannot read.
func schtasksStdout(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "schtasks.exe", args...).Output()
}

// taskExists proves absence by enumeration, without parsing schtasks' localized text or catch-all exit code.
func taskExists(ctx context.Context, name string) (bool, error) {
	out, err := schtasksStdout(ctx, "/Query", "/FO", "CSV", "/NH")
	if err != nil {
		return false, errors.New(commandError(err, out))
	}
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	for {
		record, err := r.Read()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("parse task enumeration: %w", err)
		}
		if len(record) > 0 && strings.EqualFold(strings.TrimSpace(record[0]), name) {
			return true, nil
		}
	}
}

func commandError(err error, out []byte) string {
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		return err.Error()
	}
	return fmt.Sprintf("%v: %s", err, detail)
}
