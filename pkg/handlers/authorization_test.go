package handlers

import (
	"os/user"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// currentUserName returns the username of the current user.
func currentUserName() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func TestNewUserAuthorizer(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{"user1", "user2"},
		DenyUsers:  []string{"baduser"},
	}
	logger := logrus.New()
	logger.SetOutput(nil) // Prevent test output clutter

	authorizer := NewUserAuthorizer(cfg, logger)
	if authorizer == nil {
		t.Fatal("Expected authorizer to be created, got nil")
	}

	if authorizer.config != cfg {
		t.Error("Authorizer config not set correctly")
	}

	if authorizer.logger != logger {
		t.Error("Authorizer logger not set correctly")
	}
}

func TestIsUserAllowed_EmptyLists(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{},
		DenyUsers:  []string{},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// With empty lists, all users should be allowed
	if !authorizer.IsUserAllowed("testuser", "192.168.1.100:22") {
		t.Error("Expected user to be allowed with empty AllowUsers and DenyUsers")
	}
}

func TestIsUserAllowed_DenyUsers(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{},
		DenyUsers:  []string{"baduser", "evil*"},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Denied users should be rejected
	if authorizer.IsUserAllowed("baduser", "192.168.1.100:22") {
		t.Error("Expected baduser to be denied")
	}

	if authorizer.IsUserAllowed("evilhacker", "192.168.1.100:22") {
		t.Error("Expected evilhacker to be denied by wildcard pattern")
	}

	// Non-denied users should be allowed
	if !authorizer.IsUserAllowed("gooduser", "192.168.1.100:22") {
		t.Error("Expected gooduser to be allowed")
	}
}

func TestIsUserAllowed_AllowUsers(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{"admin", "dev*", "*@trusted.com"},
		DenyUsers:  []string{},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Allowed users should be accepted
	if !authorizer.IsUserAllowed("admin", "192.168.1.100:22") {
		t.Error("Expected admin to be allowed")
	}

	if !authorizer.IsUserAllowed("developer", "192.168.1.100:22") {
		t.Error("Expected developer to be allowed by wildcard pattern")
	}

	if !authorizer.IsUserAllowed("anyone", "trusted.com:22") {
		t.Error("Expected user from trusted.com to be allowed")
	}

	// Non-allowed users should be rejected
	if authorizer.IsUserAllowed("hacker", "192.168.1.100:22") {
		t.Error("Expected hacker to be denied")
	}
}

func TestIsUserAllowed_DenyTakesPrecedence(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{"dev*"},
		DenyUsers:  []string{"devops"},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// User matches both allow and deny - deny should take precedence
	if authorizer.IsUserAllowed("devops", "192.168.1.100:22") {
		t.Error("Expected devops to be denied despite matching AllowUsers pattern")
	}

	// User matches only allow pattern
	if !authorizer.IsUserAllowed("developer", "192.168.1.100:22") {
		t.Error("Expected developer to be allowed")
	}
}

func TestIsUserAllowed_UserAtHost(t *testing.T) {
	cfg := &config.Config{
		AllowUsers: []string{"admin@server.local", "dev*@*.dev.com"},
		DenyUsers:  []string{"test@blocked.com"},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Test exact user@host match
	if !authorizer.IsUserAllowed("admin", "server.local:22") {
		t.Error("Expected admin@server.local to be allowed")
	}

	// Test wildcard user@host match
	if !authorizer.IsUserAllowed("developer", "app.dev.com:8080") {
		t.Error("Expected developer@app.dev.com to be allowed")
	}

	// Test deny user@host
	if authorizer.IsUserAllowed("test", "blocked.com:22") {
		t.Error("Expected test@blocked.com to be denied")
	}

	// Test user from different host (should be denied when AllowUsers specified)
	if authorizer.IsUserAllowed("admin", "other.com:22") {
		t.Error("Expected admin@other.com to be denied")
	}
}

func TestIsRootLoginAllowed_Yes(t *testing.T) {
	cfg := &config.Config{
		PermitRootLogin: "yes",
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Root should be allowed with any auth method
	if !authorizer.IsRootLoginAllowed("root", "password") {
		t.Error("Expected root password login to be allowed")
	}

	if !authorizer.IsRootLoginAllowed("root", "publickey") {
		t.Error("Expected root public key login to be allowed")
	}

	// Non-root users should always be allowed
	if !authorizer.IsRootLoginAllowed("user", "password") {
		t.Error("Expected non-root user to be allowed")
	}
}

func TestIsRootLoginAllowed_No(t *testing.T) {
	cfg := &config.Config{
		PermitRootLogin: "no",
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Root should be denied with any auth method
	if authorizer.IsRootLoginAllowed("root", "password") {
		t.Error("Expected root password login to be denied")
	}

	if authorizer.IsRootLoginAllowed("root", "publickey") {
		t.Error("Expected root public key login to be denied")
	}

	// Non-root users should still be allowed
	if !authorizer.IsRootLoginAllowed("user", "password") {
		t.Error("Expected non-root user to be allowed")
	}
}

func TestIsRootLoginAllowed_ProhibitPassword(t *testing.T) {
	cfg := &config.Config{
		PermitRootLogin: "prohibit-password",
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Root password login should be denied
	if authorizer.IsRootLoginAllowed("root", "password") {
		t.Error("Expected root password login to be denied")
	}

	// Root public key login should be allowed
	if !authorizer.IsRootLoginAllowed("root", "publickey") {
		t.Error("Expected root public key login to be allowed")
	}

	// Non-root users should be allowed
	if !authorizer.IsRootLoginAllowed("user", "password") {
		t.Error("Expected non-root user password login to be allowed")
	}
}

func TestIsRootLoginAllowed_ForcedCommandsOnly(t *testing.T) {
	cfg := &config.Config{
		PermitRootLogin: "forced-commands-only",
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Root password login should be denied
	if authorizer.IsRootLoginAllowed("root", "password") {
		t.Error("Expected root password login to be denied")
	}

	// Root public key login should be allowed (command validation happens later)
	if !authorizer.IsRootLoginAllowed("root", "publickey") {
		t.Error("Expected root public key login to be allowed")
	}
}

// TestIsRootForcedCommandsRequired tests the forced-commands-only check.
func TestIsRootForcedCommandsRequired(t *testing.T) {
	tests := []struct {
		name            string
		permitRootLogin string
		username        string
		expected        bool
	}{
		{
			name:            "Root with forced-commands-only requires command",
			permitRootLogin: "forced-commands-only",
			username:        "root",
			expected:        true,
		},
		{
			name:            "Non-root with forced-commands-only does not require command",
			permitRootLogin: "forced-commands-only",
			username:        "admin",
			expected:        false,
		},
		{
			name:            "Root with yes does not require command",
			permitRootLogin: "yes",
			username:        "root",
			expected:        false,
		},
		{
			name:            "Root with prohibit-password does not require command",
			permitRootLogin: "prohibit-password",
			username:        "root",
			expected:        false,
		},
		{
			name:            "Root with no does not require command (denied by other check)",
			permitRootLogin: "no",
			username:        "root",
			expected:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{PermitRootLogin: tc.permitRootLogin}
			logger, _ := test.NewNullLogger()
			authorizer := NewUserAuthorizer(cfg, logger)

			result := authorizer.IsRootForcedCommandsRequired(tc.username)
			if result != tc.expected {
				t.Errorf("IsRootForcedCommandsRequired(%q) = %v, expected %v", tc.username, result, tc.expected)
			}
		})
	}
}

// TestIsGroupAllowed_EmptyLists tests that all users are allowed when no group restrictions.
func TestIsGroupAllowed_EmptyLists(t *testing.T) {
	cfg := &config.Config{
		AllowGroups: []string{},
		DenyGroups:  []string{},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// With empty lists and assuming we can't look up nonexistent user's groups,
	// we should still allow because no restrictions are configured
	// (the function returns true when no group restrictions are set, even on lookup failure)
	result := authorizer.IsGroupAllowed("somefakeuser12345")
	// Since no restrictions configured, should return true even on lookup failure
	if !result {
		t.Error("Expected user to be allowed when no group restrictions configured")
	}
}

// TestIsGroupAllowed_NonexistentUserWithRestrictions tests lookup failure handling.
func TestIsGroupAllowed_NonexistentUserWithRestrictions(t *testing.T) {
	cfg := &config.Config{
		AllowGroups: []string{"sshusers"},
		DenyGroups:  []string{},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// With AllowGroups set, a user we can't look up should be denied
	result := authorizer.IsGroupAllowed("nonexistent_user_xyz_12345")
	if result {
		t.Error("Expected nonexistent user to be denied when AllowGroups is set")
	}
}

// TestIsGroupAllowed_DenyGroupsWithRestrictions tests lookup failure handling with DenyGroups.
func TestIsGroupAllowed_DenyGroupsWithRestrictions(t *testing.T) {
	cfg := &config.Config{
		AllowGroups: []string{},
		DenyGroups:  []string{"badgroup"},
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// With DenyGroups set, a user we can't look up should be denied for safety
	result := authorizer.IsGroupAllowed("nonexistent_user_xyz_12345")
	if result {
		t.Error("Expected nonexistent user to be denied when DenyGroups is set")
	}
}

// TestGetUserGroups tests the group lookup functionality with the current user.
func TestGetUserGroups(t *testing.T) {
	cfg := &config.Config{}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Get current user to test with a real user
	currentUser, err := getCurrentTestUser()
	if err != nil {
		t.Skipf("Cannot get current user for testing: %v", err)
	}

	groups, err := authorizer.getUserGroups(currentUser)
	if err != nil {
		t.Fatalf("getUserGroups failed for current user: %v", err)
	}

	// Current user should have at least one group
	if len(groups) == 0 {
		t.Error("Expected at least one group for current user")
	}

	t.Logf("Current user %s belongs to groups: %v", currentUser, groups)
}

// TestIsGroupAllowed_CurrentUser tests group checking with the actual current user.
func TestIsGroupAllowed_CurrentUser(t *testing.T) {
	currentUser, err := getCurrentTestUser()
	if err != nil {
		t.Skipf("Cannot get current user for testing: %v", err)
	}

	// Get current user's actual groups
	cfg := &config.Config{}
	logger, _ := test.NewNullLogger()
	tempAuth := NewUserAuthorizer(cfg, logger)
	groups, err := tempAuth.getUserGroups(currentUser)
	if err != nil || len(groups) == 0 {
		t.Skipf("Cannot get groups for testing: %v", err)
	}

	t.Run("AllowGroups matches current user's group", func(t *testing.T) {
		cfg := &config.Config{
			AllowGroups: []string{groups[0]}, // Use first actual group
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		if !authorizer.IsGroupAllowed(currentUser) {
			t.Errorf("Expected user %s to be allowed (member of %s)", currentUser, groups[0])
		}
	})

	t.Run("AllowGroups does not match current user", func(t *testing.T) {
		cfg := &config.Config{
			AllowGroups: []string{"nonexistent_group_xyz"},
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		if authorizer.IsGroupAllowed(currentUser) {
			t.Error("Expected user to be denied when not in AllowGroups")
		}
	})

	t.Run("DenyGroups matches current user's group", func(t *testing.T) {
		cfg := &config.Config{
			DenyGroups: []string{groups[0]}, // Deny first actual group
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		if authorizer.IsGroupAllowed(currentUser) {
			t.Errorf("Expected user %s to be denied (member of denied group %s)", currentUser, groups[0])
		}
	})

	t.Run("DenyGroups does not match current user", func(t *testing.T) {
		cfg := &config.Config{
			DenyGroups: []string{"nonexistent_group_xyz"},
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		if !authorizer.IsGroupAllowed(currentUser) {
			t.Error("Expected user to be allowed when not in DenyGroups")
		}
	})

	t.Run("DenyGroups takes precedence over AllowGroups", func(t *testing.T) {
		cfg := &config.Config{
			AllowGroups: []string{groups[0]},
			DenyGroups:  []string{groups[0]}, // Same group in both
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		// DenyGroups should take precedence
		if authorizer.IsGroupAllowed(currentUser) {
			t.Error("Expected user to be denied when in both AllowGroups and DenyGroups")
		}
	})

	t.Run("AllowGroups with wildcard", func(t *testing.T) {
		// Create a pattern that matches the first group
		pattern := groups[0][:len(groups[0])/2+1] + "*"
		cfg := &config.Config{
			AllowGroups: []string{pattern},
		}
		logger, _ := test.NewNullLogger()
		authorizer := NewUserAuthorizer(cfg, logger)

		if !authorizer.IsGroupAllowed(currentUser) {
			t.Errorf("Expected user to be allowed by wildcard pattern %s matching group %s", pattern, groups[0])
		}
	})
}

// getCurrentTestUser returns the username of the current process owner.
func getCurrentTestUser() (string, error) {
	return currentUserName()
}

func TestIsRootLoginAllowed_InvalidValue(t *testing.T) {
	cfg := &config.Config{
		PermitRootLogin: "invalid-value",
	}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	// Should default to prohibit-password behavior
	if authorizer.IsRootLoginAllowed("root", "password") {
		t.Error("Expected root password login to be denied with invalid PermitRootLogin value")
	}

	if !authorizer.IsRootLoginAllowed("root", "publickey") {
		t.Error("Expected root public key login to be allowed with invalid PermitRootLogin value")
	}
}

func TestMatchWildcard(t *testing.T) {
	cfg := &config.Config{}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	tests := []struct {
		pattern  string
		text     string
		expected bool
	}{
		{"admin", "admin", true},
		{"admin", "user", false},
		{"admin*", "admin", true},
		{"admin*", "administrator", true},
		{"admin*", "user", false},
		{"*admin", "admin", true},
		{"*admin", "sysadmin", true},
		{"*admin", "user", false},
		{"dev?", "dev1", true},
		{"dev?", "dev2", true},
		{"dev?", "dev", false},
		{"dev?", "dev12", false},
		{"*.com", "example.com", true},
		{"*.com", "test.org", false},
	}

	for _, test := range tests {
		result := authorizer.matchWildcard(test.pattern, test.text)
		if result != test.expected {
			t.Errorf("matchWildcard(%q, %q) = %v, expected %v", test.pattern, test.text, result, test.expected)
		}
	}
}

func TestMatchUserPattern(t *testing.T) {
	cfg := &config.Config{}
	logger, _ := test.NewNullLogger()
	authorizer := NewUserAuthorizer(cfg, logger)

	tests := []struct {
		pattern  string
		username string
		host     string
		expected bool
	}{
		// Simple username patterns
		{"admin", "admin", "host.com", true},
		{"admin", "user", "host.com", false},
		{"admin*", "administrator", "host.com", true},

		// User@host patterns
		{"admin@host.com", "admin", "host.com", true},
		{"admin@host.com", "admin", "other.com", false},
		{"admin@host.com", "user", "host.com", false},
		{"*@trusted.com", "anyone", "trusted.com", true},
		{"*@trusted.com", "anyone", "untrusted.com", false},
		{"admin@*.local", "admin", "server.local", true},
		{"admin@*.local", "admin", "server.remote", false},

		// @host patterns (any user from host)
		{"@trusted.com", "anyone", "trusted.com", true},
		{"@trusted.com", "anyone", "untrusted.com", false},
		{"@*.local", "user", "server.local", true},
		{"@*.local", "user", "server.remote", false},
	}

	for _, test := range tests {
		result := authorizer.matchUserPattern(test.pattern, test.username, test.host)
		if result != test.expected {
			t.Errorf("matchUserPattern(%q, %q, %q) = %v, expected %v",
				test.pattern, test.username, test.host, result, test.expected)
		}
	}
}

func TestParseAuthorizedKeyOptions_NoOptions(t *testing.T) {
	line := "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host"
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if keyPart != line {
		t.Errorf("Expected key part to be unchanged, got %q", keyPart)
	}

	if options == nil {
		t.Error("Expected options struct to be created")
	}

	if options.Command != "" {
		t.Error("Expected no command option")
	}
}

func TestParseAuthorizedKeyOptions_WithCommand(t *testing.T) {
	line := `command="/bin/backup" ssh-rsa AAAAB3NzaC1yc2EAAAA... backup@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(keyPart, "ssh-rsa") {
		t.Error("Expected key part to contain ssh-rsa")
	}

	if options.Command != "/bin/backup" {
		t.Errorf("Expected command=/bin/backup, got %q", options.Command)
	}
}

func TestParseAuthorizedKeyOptions_MultipleOptions(t *testing.T) {
	line := `no-port-forwarding,no-pty,command="/bin/restricted" ssh-rsa AAAAB3NzaC1yc2EAAAA... restricted@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(keyPart, "ssh-rsa") {
		t.Error("Expected key part to contain ssh-rsa")
	}

	if !options.NoPortForwarding {
		t.Error("Expected no-port-forwarding to be set")
	}

	if !options.NoPTY {
		t.Error("Expected no-pty to be set")
	}

	if options.Command != "/bin/restricted" {
		t.Errorf("Expected command=/bin/restricted, got %q", options.Command)
	}
}

func TestParseAuthorizedKeyOptions_FromRestriction(t *testing.T) {
	line := `from="192.168.1.0/24,10.0.0.1" ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(keyPart, "ssh-rsa") {
		t.Error("Expected key part to contain ssh-rsa")
	}

	expectedFrom := []string{"192.168.1.0/24", "10.0.0.1"}
	if len(options.From) != len(expectedFrom) {
		t.Errorf("Expected %d from entries, got %d", len(expectedFrom), len(options.From))
	}

	for i, expected := range expectedFrom {
		if i >= len(options.From) || options.From[i] != expected {
			t.Errorf("Expected from[%d]=%q, got %q", i, expected, options.From[i])
		}
	}
}

func TestParseAuthorizedKeyOptions_QuotedValues(t *testing.T) {
	line := `command="echo \"hello world\"",environment="HOME=/tmp" ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(keyPart, "ssh-rsa") {
		t.Error("Expected key part to contain ssh-rsa")
	}

	expectedCommand := `echo \"hello world\"`
	if options.Command != expectedCommand {
		t.Errorf("Expected command=%q, got %q", expectedCommand, options.Command)
	}

	if options.Environment["HOME"] != "/tmp" {
		t.Errorf("Expected HOME=/tmp, got %q", options.Environment["HOME"])
	}
}

func TestParseAuthorizedKeyOptions_EmptyLine(t *testing.T) {
	_, _, err := ParseAuthorizedKeyOptions("")
	if err == nil {
		t.Error("Expected error for empty line")
	}

	_, _, err = ParseAuthorizedKeyOptions("# comment")
	if err == nil {
		t.Error("Expected error for comment line")
	}
}

func TestParseAuthorizedKeyOptions_InvalidKey(t *testing.T) {
	line := `command="/bin/test" invalid-key-type AAAAB3... user@host`
	_, _, err := ParseAuthorizedKeyOptions(line)
	if err == nil {
		t.Error("Expected error for invalid key type")
	}
}

// TestParseAuthorizedKeyOptions_BareRestrictKeyword is a regression test:
// standard OpenSSH options like a bare "restrict" (or "cert-authority",
// "no-touch-required", "verify-required") don't contain "=" and aren't in
// any fixed keyword substring list, so a naive heuristic based on matching
// specific option keywords would fail to recognize this line as having
// options at all, misparsing "restrict" itself as if it were the key type
// and causing the whole entry to be rejected downstream.
func TestParseAuthorizedKeyOptions_BareRestrictKeyword(t *testing.T) {
	line := `restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.HasPrefix(keyPart, "ssh-ed25519") {
		t.Errorf("Expected key part to start with ssh-ed25519, got %q", keyPart)
	}

	if options == nil {
		t.Fatal("Expected options struct to be created")
	}
}

// TestParseAuthorizedKeyOptions_RestrictWithOtherOptions verifies "restrict"
// combined with a recognized keyword (e.g. via comma) still parses
// correctly, and that the recognized keyword's effect is applied.
func TestParseAuthorizedKeyOptions_RestrictWithOtherOptions(t *testing.T) {
	line := `restrict,pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host`
	keyPart, options, err := ParseAuthorizedKeyOptions(line)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.HasPrefix(keyPart, "ssh-ed25519") {
		t.Errorf("Expected key part to start with ssh-ed25519, got %q", keyPart)
	}

	if !options.PTY {
		t.Error("Expected pty option to be set")
	}
}
