//go:build windows

package crashjournal

import "os"

// Windows refuses signal 0, so os.FindProcess's handle is the probe; it errs toward alive, which never invents a crash.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
