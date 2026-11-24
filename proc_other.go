//go:build !windows && !linux

package main

import (
	"fmt"
	"runtime"
)

func findWarframePID() (uint32, error) {
	return 0, fmt.Errorf("process scanning not implemented on %s", runtime.GOOS)
}

func readProcessMemoryAt(pid uint32, addr uintptr, size int) ([]byte, error) {
	return nil, fmt.Errorf("process scanning not implemented on %s", runtime.GOOS)
}

func scanProcessMemory(pid uint32, onChunk func(baseAddr uintptr, chunk []byte) bool) error {
	return fmt.Errorf("process scanning not implemented on %s", runtime.GOOS)
}
