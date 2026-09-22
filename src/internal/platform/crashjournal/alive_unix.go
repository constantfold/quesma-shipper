//go:build !windows

package crashjournal

import (
	"os"
	"syscall"
)

// alive separates a concurrent run from a dead one; signal 0 checks existence and delivers nothing.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
