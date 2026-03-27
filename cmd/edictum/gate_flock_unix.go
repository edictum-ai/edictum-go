//go:build !windows

package main

import (
	"os"
	"syscall"
)

// lockFile acquires an exclusive advisory lock on f.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}
