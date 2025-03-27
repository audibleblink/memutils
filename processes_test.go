//go:build windows

package memutils

import (
	"testing"
)

func TestProcesses(t *testing.T) {
	
	// Get all processes
	procs, err := Processes()
	if err != nil {
		t.Fatalf("Processes() failed: %v", err)
	}

	// Verify we got some processes
	if len(procs) == 0 {
		t.Error("Processes() returned empty list")
	}

	// Verify some common processes exist
	systemProcessFound := false
	for _, p := range procs {
		if p.Exe == "System" || p.Exe == "System.exe" {
			systemProcessFound = true
			break
		}
	}

	if !systemProcessFound {
		t.Log("No System process found, but this might be normal depending on permissions")
	}
}

func TestNewWindowsProcess(t *testing.T) {
	
	// This test is more challenging to implement directly because it requires
	// a ProcessEntry32 structure, which is typically obtained from the Windows API.
	// We'll test it indirectly through the Processes function

	procs, err := Processes()
	if err != nil {
		t.Fatalf("Processes() failed, can't test NewWindowsProcess: %v", err)
	}

	// Just check that we have non-zero values in the returned processes
	if len(procs) > 0 {
		// Check first process has valid PID
		if procs[0].Pid == 0 {
			t.Error("Process has PID 0, which is unexpected")
		}

		// Check process has name
		if procs[0].Exe == "" {
			t.Error("Process executable name is empty")
		}
	}
}

func TestPidForName(t *testing.T) {
	
	// Get all processes
	procs, err := Processes()
	if err != nil {
		t.Fatalf("Processes() failed, can't test PidForName: %v", err)
	}

	// Skip test if no processes found
	if len(procs) == 0 {
		t.Skip("No processes found to test PidForName")
	}

	// Use the first process name to test PidForName
	testProc := procs[0]
	pid := PidForName(testProc.Exe)

	// Verify PID matches
	if pid != testProc.Pid {
		t.Errorf("PidForName(%s) returned %d, expected %d", testProc.Exe, pid, testProc.Pid)
	}

	// Test with non-existent process
	nonExistentPid := PidForName("ThisProcessShouldNotExist12345")
	if nonExistentPid != 0 {
		t.Errorf("PidForName for non-existent process returned %d, expected 0", nonExistentPid)
	}
}