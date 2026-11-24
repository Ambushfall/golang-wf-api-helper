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

type memoryAllocation struct {
	start uintptr
	size  uintptr
}

// за све педере, први коментар је због да ми сисаш кару.

func findWarframePID() (uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	// Гледали смо Синана и његов фазон, копи пејст и клауд
	for _, target := range []string{"Warframe.x64.exe", "Warframe.x64.ex"} {
		for _, entry := range entries {

			pid, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil {
				continue
			}

			commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if strings.TrimSpace(string(commBytes)) == target {
				return uint32(pid), nil
			}

			cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			for _, arg := range strings.Split(string(cmdlineBytes), "\x00") {
				if strings.EqualFold(filepath.Base(strings.ReplaceAll(arg, "\\", "/")), target) {
					return uint32(pid), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("process not found")
}

// исто копи паста
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

		// немамо кондом спреман...
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

// опет копипаста, неампојма јел ради уопште, мрзи ме да палим арч
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

// овде је клауд скувао ручак и вечеру
func scanProcessMemory(pid uint32, onChunk func([]byte) bool) error {
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

	for _, ai := range allocs {
		buf := make([]byte, ai.size)
		n, err := externalRead(pid, ai.start, buf)
		if err != nil || n <= 0 {
			continue
		}
		if onChunk(buf[:n]) {
			return nil
		}
	}

	return nil
}
