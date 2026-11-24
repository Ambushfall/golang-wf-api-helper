//go:build !windows && !linux

package main

import (
	"fmt"
	"runtime"
)

// Ако успеш овде да завршиш, место ти је у паклу буквално.
func findWarframePID() (uint32, error) {
	return 0, fmt.Errorf("process scanning not implemented on %s", runtime.GOOS)
}

// Пуца ми курац да правим тест, сисај га перо.
func scanProcessMemory(pid uint32, onChunk func([]byte) bool) error {
	return fmt.Errorf("process scanning not implemented on %s", runtime.GOOS)
}
