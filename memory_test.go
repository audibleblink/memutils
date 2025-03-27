//go:build windows

package memutils

import (
	"bytes"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestHandleForPid(t *testing.T) {
	
	// Test current process (pid 0)
	handle, err := HandleForPid(0, windows.PROCESS_QUERY_INFORMATION)
	if err != nil {
		t.Errorf("HandleForPid(0) failed: %v", err)
	}
	if handle == 0 {
		t.Error("HandleForPid(0) returned 0 handle")
	}

	// Test with actual PID
	pid := os.Getpid()
	handle, err = HandleForPid(pid, windows.PROCESS_QUERY_INFORMATION)
	if err != nil {
		t.Errorf("HandleForPid(%d) failed: %v", pid, err)
	}
	if handle == 0 {
		t.Error("HandleForPid with actual PID returned 0 handle")
	} else {
		windows.CloseHandle(handle)
	}
}

func TestProcBasicInfo(t *testing.T) {
	
	// Get handle to current process
	handle := windows.CurrentProcess()

	// Get process basic info
	pbi, err := ProcBasicInfo(handle)
	if err != nil {
		t.Fatalf("ProcBasicInfo failed: %v", err)
	}

	// Basic validation
	if pbi.PebBaseAddress == nil {
		t.Error("ProcBasicInfo returned nil PebBaseAddress")
	}
	if pbi.UniqueProcessId == 0 {
		t.Error("ProcBasicInfo returned 0 for UniqueProcessId")
	}
}

func TestGetPEB(t *testing.T) {
	
	// Get handle to current process
	handle := windows.CurrentProcess()

	// Get PEB
	peb, err := GetPEB(handle)
	if err != nil {
		t.Fatalf("GetPEB failed: %v", err)
	}

	// Basic validation
	if peb.ImageBaseAddress == 0 {
		t.Error("GetPEB returned 0 for ImageBaseAddress")
	}
}

func TestReadMemory(t *testing.T) {
	
	// Create test data
	testData := []byte("test data for ReadMemory")
	
	// Get handle to current process
	handle := windows.CurrentProcess()
	
	// Read the data from our own memory
	result := make([]byte, len(testData))
	err := ReadMemory(handle, unsafe.Pointer(&testData[0]), unsafe.Pointer(&result[0]), uint32(len(testData)))
	if err != nil {
		t.Fatalf("ReadMemory failed: %v", err)
	}
	
	// Verify the data was read correctly
	if !bytes.Equal(testData, result) {
		t.Errorf("ReadMemory data mismatch. Got %v, expected %v", result, testData)
	}
}

// TestPopulateStrings is harder to test directly because it requires a valid NTUnicodeString structure
// from another process. This would typically be tested with integration tests.

// TestCarveOutPE requires more complex setup to have a valid PE file in memory to extract.
// This would be better suited for integration tests with specific test binaries.

func TestJuggleWrite(t *testing.T) {
	skipIfNonAdmin(t)
	
	// This test would require modifying memory in a process, which can be risky
	// and requires elevated privileges. This is better suited for integration tests
	// with specific test binaries where we control the memory being modified.
	t.Skip("Skipping JuggleWrite test as it requires memory modification")
}