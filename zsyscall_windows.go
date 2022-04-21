// Code generated by 'go generate'; DO NOT EDIT.

package memutils

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

var _ unsafe.Pointer

var (
	bpGlobal, bperr = bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
)

func NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint64, protect uint64) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(processHandle), uintptr(unsafe.Pointer(baseAddress)), uintptr(zeroBits), uintptr(unsafe.Pointer(regionSize)), uintptr(allocationType), uintptr(protect))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtOpenProcess(processHandle *windows.Handle, desiredAccess windows.ACCESS_MASK, objectAttributes *windows.OBJECT_ATTRIBUTES, clientID *ClientID) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtOpenProcess")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(unsafe.Pointer(processHandle)), uintptr(desiredAccess), uintptr(unsafe.Pointer(objectAttributes)), uintptr(unsafe.Pointer(clientID)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtProtectVirtualMemory(processHandle windows.Handle, baseAddress *uintptr, numberOfBytesToProtect *uintptr, newAccessProtection int64, OldAccessProtection *int64) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(processHandle), uintptr(unsafe.Pointer(baseAddress)), uintptr(unsafe.Pointer(numberOfBytesToProtect)), uintptr(newAccessProtection), uintptr(unsafe.Pointer(OldAccessProtection)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtCreateThreadEx(threadHandle *windows.Handle, desiredAccess windows.ACCESS_MASK, objectAttributes *windows.OBJECT_ATTRIBUTES, processHandle windows.Handle, startAddress uintptr, parameter uintptr, createSuspended bool, stackZeroBits uint32, sizeOfStackCommit uint32, sizeOfStackReserve uint32, lpbytesbuffer uint32) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtCreateThreadEx")
	if e != nil {
		err = e
		return
	}
	var _p0 uint32
	if createSuspended {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(unsafe.Pointer(threadHandle)), uintptr(desiredAccess), uintptr(unsafe.Pointer(objectAttributes)), uintptr(processHandle), uintptr(startAddress), uintptr(parameter), uintptr(_p0), uintptr(stackZeroBits), uintptr(sizeOfStackCommit), uintptr(sizeOfStackReserve), uintptr(lpbytesbuffer))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtWriteVirtualMemory(processHandle windows.Handle, baseAddress uintptr, buffer *byte, numberOfBytesToWrite uintptr, numberOfBytesWritten *uint32) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(processHandle), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(numberOfBytesToWrite), uintptr(unsafe.Pointer(numberOfBytesWritten)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtReadVirtualMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtReadVirtualMemory")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtResumeThread(threadHandle windows.Handle, previousSuspendCount *uint32) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtResumeThread")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(threadHandle), uintptr(unsafe.Pointer(previousSuspendCount)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}
