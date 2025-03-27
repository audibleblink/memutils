//go:build windows

package memutils

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTokenOwner(t *testing.T) {
	
	// Get the current process token
	var token windows.Token
	currentProcess := windows.CurrentProcess()
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("Failed to open process token: %v", err)
	}
	defer token.Close()

	// Test TokenOwner function
	owner, err := TokenOwner(token)
	if err != nil {
		t.Fatalf("TokenOwner failed: %v", err)
	}

	if owner == "" {
		t.Error("TokenOwner returned empty string")
	}
	t.Logf("Current process token owner: %s", owner)
}

func TestTokenOwnerFromPid(t *testing.T) {
	
	// Get current process PID
	pid := os.Getpid()

	// Test TokenOwnerFromPid function
	owner, err := TokenOwnerFromPid(pid)
	if err != nil {
		t.Fatalf("TokenOwnerFromPid failed: %v", err)
	}

	if owner == "" {
		t.Error("TokenOwnerFromPid returned empty string")
	}
	t.Logf("Process %d token owner: %s", pid, owner)
}

func TestTokenForPid(t *testing.T) {
	
	// Get current process PID
	pid := os.Getpid()

	// Test TokenForPid function
	token, err := TokenForPid(pid, windows.TOKEN_QUERY)
	if err != nil {
		t.Fatalf("TokenForPid failed: %v", err)
	}
	defer token.Close()

	// Verify token is valid by getting token user
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser failed on token from TokenForPid: %v", err)
	}

	if tokenUser == nil {
		t.Error("GetTokenUser returned nil")
	}
}