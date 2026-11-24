//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	scanChunkSize   = 4 * 1024 * 1024
	scanOverlapSize = 128
)

type memoryAllocation struct {
	start uintptr
	size  uintptr
}

func findWarframePID() (uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, target := range []string{"Warframe.x64.exe", "Warframe.x64.ex"} {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil {
				continue
			}

			commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if strings.TrimSpace(string(commBytes)) == target {
				return uint32(pid), nil
			}

			cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			if len(cmdlineBytes) > 0 {
				argv0 := strings.SplitN(string(cmdlineBytes), "\x00", 2)[0]
				if strings.EqualFold(filepath.Base(strings.ReplaceAll(argv0, "\\", "/")), target) {
					return uint32(pid), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("process not found")
}

func getAllocations(pid uint32) ([]memoryAllocation, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, err
	}

	var allocs []memoryAllocation
	for _, line := range strings.Split(string(mapsData), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[1], "r") {
			continue
		}

		if len(fields) >= 6 && (fields[5] == "[vvar]" || fields[5] == "[vdso]" || fields[5] == "[vsyscall]") {
			continue
		}

		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}

		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}

		allocs = append(allocs, memoryAllocation{
			start: uintptr(start),
			size:  uintptr(end - start),
		})
	}

	return allocs, nil
}

func externalRead(pid uint32, addr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	localIov := []unix.Iovec{
		{Base: &buf[0], Len: uint64(len(buf))},
	}
	remoteIov := []unix.RemoteIovec{
		{Base: addr, Len: len(buf)},
	}

	return unix.ProcessVMReadv(int(pid), localIov, remoteIov, 0)
}

// readProcessMemoryAt reads an exact number of bytes at a known virtual address.
func readProcessMemoryAt(pid uint32, addr uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := externalRead(pid, addr, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// scanProcessMemory streams readable memory regions through a fixed 4 MB buffer
// and passes each chunk's starting virtual address to onChunk.
func scanProcessMemory(pid uint32, onChunk func(baseAddr uintptr, chunk []byte) bool) error {
	allocs, err := getAllocations(pid)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}

	if len(allocs) > 0 {
		var probe [1]byte
		if _, err := externalRead(pid, allocs[0].start, probe[:]); err == unix.EPERM {
			return fmt.Errorf("failed to open process: %w", err)
		}
	}

	buf := make([]byte, scanChunkSize+scanOverlapSize)

	for _, ai := range allocs {
		var offset uintptr
		carry := 0

		for offset < ai.size {
			toRead := min(ai.size-offset, uintptr(len(buf)-carry))
			n, readErr := externalRead(pid, ai.start+offset, buf[carry:carry+int(toRead)])
			if readErr != nil || n <= 0 {
				break
			}

			total := carry + n
			chunkBase := ai.start + offset - uintptr(carry)
			if onChunk(chunkBase, buf[:total]) {
				return nil
			}

			if offset+uintptr(n) >= ai.size {
				break
			}

			keep := min(total, scanOverlapSize)
			copy(buf[:keep], buf[total-keep:total])
			carry = keep
			offset += uintptr(n)
		}
	}

	return nil
}
