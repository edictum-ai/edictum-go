//go:build windows

package main

import "os"

// lockFile is a no-op on Windows. O_APPEND provides sufficient
// atomicity for the typical WAL payload size on Windows (NTFS
// guarantees atomic appends for small writes).
func lockFile(_ *os.File) error {
	return nil
}
