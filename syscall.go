package memutils

//dsys NtOpenProcess(hProcess syscall.Handle, accessMask uint64, pObjectAttrs uintptr, pClientId uintptr) (ntstatus error)
//dsys NtQueryInformationProcess(hProcess syscall.Handle, procInfoClass int32, procInfo unsafe.Pointer, procInfoLen uint32, retLen *uint32) (ntstatus error)
//dsys NtAllocateVirtualMemory(hProcess syscall.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint64, protect uint64) (err error)
//dsys NtReadVirtualMemory(hProcess syscall.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error)
//dsys NtWriteVirtualMemory(hProcess syscall.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error)
//dsys NtProtectVirtualemory(hProcess syscall.Handle, lpAddress *uintptr, dwSize *uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error)
//dsys NtCreateThreadEx(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr) (err error)

//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkdirectwinsyscall -output zsyscall_windows.go syscall.go
