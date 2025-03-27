//go:build windows

package memutils

import (
	"os"
	"strings"
	"testing"
)

// skipIfNonAdmin skips the test if not running with administrator privileges
// Note: This is a rudimentary check and may not be accurate in all cases
func skipIfNonAdmin(t *testing.T) {
	// This is a simple heuristic and not foolproof
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}

	if !strings.EqualFold(username, "Administrator") && !strings.EqualFold(username, "SYSTEM") {
		// Try to check if process has elevated privileges
		// This would ideally use a more reliable method like IsUserAnAdmin() from Windows API
		t.Skip("Skipping test as it requires administrator privileges")
	}
}
