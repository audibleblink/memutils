//go:build windows

package memutils

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/audibleblink/logerr"
	"golang.org/x/sys/windows"
)

const TH32CS_SNAPPROCESS uint32 = 0x00000002

type WindowsProcess struct {
	Pid  int
	Ppid int
	Exe  string
}

// Processes retrieves a list of all running processes in the system
// Returns a slice of WindowsProcess structures and an error if the operation fails
func Processes() ([]WindowsProcess, error) {
	log := logerr.Add("Processes")
	handle, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, log.Add("CreateToolhelp32Snapshot").Wrap(err)
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, log.Add("Process32First").Wrap(err)
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, NewWindowsProcess(&entry))

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				return results, nil
			}

			return results, log.Add("Process32Next").Wrap(err)
		}
	}
}

// NewWindowsProcess creates a WindowsProcess struct from a windows.ProcessEntry32
// Converts the process information into a more usable structure
func NewWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		Pid:  int(e.ProcessID),
		Ppid: int(e.ParentProcessID),
		Exe:  syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

// PidForName finds the process ID (PID) for a process with the given name
// Returns 0 if no process with the specified name is found
func PidForName(processName string) int {
	processes, _ := Processes()
	for _, process := range processes {
		if processName == process.Exe {
			return process.Pid
		}
	}
	return 0
}
