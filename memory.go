package memutils

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/audibleblink/logerr"
	"golang.org/x/sys/windows"
)

func HandleForPid(pid int, privs int) (handle windows.Handle, err error) {
	log := logerr.Add("HandleForPid")
	if pid == 0 {
		handle = windows.CurrentProcess()
		return
	}

	oa := unsafe.Pointer(&windows.OBJECT_ATTRIBUTES{})
	err = NtOpenProcess(handle, uint64(privs), uintptr(oa), uintptr(pid))
	// handle, err = windows.OpenProcess(uint32(attrs), true, uint32(pid))
	if err != nil {
		msg := fmt.Sprintf("OpenProcess[%d]", pid)
		err = log.Add(msg).Wrap(err)
	}
	return
}

// func MyPEB() (peb windows.PEB, err error) {
// 	pebStart := bananaphone.GetPEB()
// }

func GetPEB(handle windows.Handle) (peb windows.PEB, err error) {
	pbi, err := ProcBasicInfo(handle)
	if err != nil {
		return
	}

	err = fillPEB(handle, &pbi)
	if err != nil {
		err = fmt.Errorf("getPEB | %s", err)
		return
	}
	peb = *pbi.PebBaseAddress
	return
}

func ProcBasicInfo(handle windows.Handle) (pbi windows.PROCESS_BASIC_INFORMATION, err error) {
	pbiSize := unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})
	var returnedLen uint32
	err = windows.NtQueryInformationProcess(
		handle,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi),
		uint32(pbiSize),
		&returnedLen)
	if err != nil {
		err = logerr.Add("ProcBasicInfo").Wrap(err)
		return
	}
	return
}

func ReadMemory(hProc windows.Handle, start unsafe.Pointer, dest unsafe.Pointer, readLen uint32) error {
	return NtReadVirtualMemory(hProc, uintptr(start), (*byte)(dest), uintptr(readLen), nil)
}

func fillPEB(handle windows.Handle, pbi *windows.PROCESS_BASIC_INFORMATION) error {
	log := logerr.Add("filPEB")

	// read in top level peb
	base := unsafe.Pointer(pbi.PebBaseAddress)
	pbi.PebBaseAddress = &windows.PEB{}
	size := uint32(unsafe.Sizeof(*pbi.PebBaseAddress))
	dest := unsafe.Pointer(pbi.PebBaseAddress)
	err := ReadMemory(handle, base, dest, size)
	if err != nil {
		return log.Add("PBI").Wrap(err)
	}

	// with peb.Ldr populated with the remote Ldr pointer, re-read
	base = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	pbi.PebBaseAddress.Ldr = &windows.PEB_LDR_DATA{}
	size = uint32(unsafe.Sizeof(*pbi.PebBaseAddress.Ldr))
	dest = unsafe.Pointer(pbi.PebBaseAddress.Ldr)
	err = ReadMemory(handle, base, dest, size)
	if err != nil {
		return log.Add("peb.Ldr").Wrap(err)
	}

	// also fill peb with process_parameters
	base = unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters)
	pbi.PebBaseAddress.ProcessParameters = &windows.RTL_USER_PROCESS_PARAMETERS{}
	size = uint32(unsafe.Sizeof(*pbi.PebBaseAddress.ProcessParameters))
	dest = unsafe.Pointer(pbi.PebBaseAddress.ProcessParameters)
	err = ReadMemory(handle, base, dest, size)
	if err != nil {
		return log.Add("proc_params").Wrap(err)
	}
	return err
}

func PopulateStrings(pidHandle windows.Handle, ntString *windows.NTUnicodeString) (string, error) {
	dllNameUTF16 := make([]uint16, ntString.Length)
	base := unsafe.Pointer(ntString.Buffer)
	size := uint32(ntString.Length)
	dest := unsafe.Pointer(&dllNameUTF16[0])
	err := ReadMemory(pidHandle, base, dest, size)
	if err != nil {
		logerr.Add("PopulateStrings").Wrap(err)
	}
	return windows.UTF16ToString(dllNameUTF16), err
}

func CarveOutPE(hProc windows.Handle, peb windows.PEB, peSize uint64) (pe.File, error) {
	// read in the PE from process memory
	peData := make([]byte, peSize)
	err := ReadMemory(
		hProc,
		unsafe.Pointer(peb.ImageBaseAddress),
		unsafe.Pointer(&peData[0]),
		uint32(peSize),
	)
	if err != nil {
		logerr.Add("CarveOutPE").Wrap(err)
	}

	// convert the memory bytes into an in-memory, parsed, PE
	peReader := bytes.NewReader(peData)
	peFile, err := pe.NewFileFromMemory(peReader)
	if err != nil {
		return pe.File{}, logerr.Add("NewFileFromMemory").Wrap(err)
	}

	return *peFile, err
}

func JuggleWrite(hProcess windows.Handle, baseAddr uintptr, data []byte) error {
	log := logerr.Add("JuggleWrite")

	var (
		oldProtect uint32
		old        uint32
		written    uintptr
	)

	err := windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		return log.Add("VirtualProtectEx[rw]").Wrap(err)
	}
	err = windows.WriteProcessMemory(windows.Handle(hProcess), baseAddr, &data[0], uintptr(len(data)), &written)
	if err != nil {
		return log.Add("WriteProcessMemory").Wrap(err)
	}
	err = windows.VirtualProtectEx(windows.Handle(hProcess), baseAddr, 1, oldProtect, &old)
	if err != nil {
		return log.Add("VirtualProtectEx[rx]").Wrap(err)
	}
	return err
}
