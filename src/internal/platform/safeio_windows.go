package platform

import "syscall"

// FILE_FLAG_OPEN_REPARSE_POINT opens a symlink itself, which fstat then reports as irregular.
// Windows has no POSIX modes, so ReadPrivate skips its mode check.
const (
	openFlags                 = syscall.FILE_FLAG_OPEN_REPARSE_POINT | syscall.O_CLOEXEC
	platformSupportsFileModes = false
)
