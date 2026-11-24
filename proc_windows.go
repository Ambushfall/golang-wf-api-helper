//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	scanChunkSize   = 4 * 1024 * 1024
	scanOverlapSize = 128
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

// readProcessMemoryAt reads an exact number of bytes at a known virtual address.
func readProcessMemoryAt(pid uint32, addr uintptr, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}

	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	buf := make([]byte, size)
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(handle, addr, &buf[0], uintptr(size), &bytesRead); err != nil {
		return nil, err
	}
	return buf[:bytesRead], nil
}

// scanProcessMemory streams readable memory regions through a fixed 4 MB buffer
// and passes each chunk's starting virtual address to onChunk.
func scanProcessMemory(pid uint32, onChunk func(baseAddr uintptr, chunk []byte) bool) error {
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(handle)

	buf := make([]byte, scanChunkSize+scanOverlapSize)
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
			var offset uintptr
			carry := 0

			for offset < mbi.RegionSize {
				toRead := min(mbi.RegionSize-offset, uintptr(len(buf)-carry))
				var bytesRead uintptr
				readErr := windows.ReadProcessMemory(
					handle,
					mbi.BaseAddress+offset,
					&buf[carry],
					toRead,
					&bytesRead,
				)
				if readErr != nil || bytesRead == 0 {
					break
				}

				total := carry + int(bytesRead)
				chunkBase := mbi.BaseAddress + offset - uintptr(carry)
				if onChunk(chunkBase, buf[:total]) {
					return nil
				}

				if offset+bytesRead >= mbi.RegionSize {
					break
				}

				keep := min(total, scanOverlapSize)
				copy(buf[:keep], buf[total-keep:total])
				carry = keep
				offset += bytesRead
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
