//go:build unix

package common

import (
	"os"
	"syscall"
)

// ReExec execs the binary now at this path with the same argv and environment; the caller guards against loops.
func ReExec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
