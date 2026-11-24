//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func findWarframePID() (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		exe := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exe, "Warframe.x64.exe") {
			return entry.ProcessID, nil
		}
	}
	return 0, fmt.Errorf("process not found")
}

// scanProcessMemory iterates over committed, readable memory regions and invokes onChunk for each buffer.
// Return true from onChunk to stop scanning early.
func scanProcessMemory(pid uint32, onChunk func([]byte) bool) error {
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(handle)

	var addr uintptr
	var mbi windows.MemoryBasicInformation

	for {
		err := windows.VirtualQueryEx(handle, addr, &mbi, unsafe.Sizeof(mbi))
		if err != nil || mbi.RegionSize == 0 {
			break
		}

		readable := mbi.State == windows.MEM_COMMIT &&
			(mbi.Protect&windows.PAGE_NOACCESS) == 0 &&
			(mbi.Protect&windows.PAGE_GUARD) == 0

		if readable {
			buf := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			if err := windows.ReadProcessMemory(handle, mbi.BaseAddress, &buf[0], mbi.RegionSize, &bytesRead); err == nil && bytesRead > 0 {
				if onChunk(buf[:bytesRead]) {
					return nil
				}
			}
		}

		nextAddr := mbi.BaseAddress + mbi.RegionSize
		if nextAddr <= addr {
			break
		}
		addr = nextAddr
	}
	return nil
}
