package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Test loading defaults when no config file exists
	cfg, err := Load("/nonexistent/config/file")
	if err != nil {
		t.Fatalf("Load() with nonexistent file should return defaults, got error: %v", err)
	}

	// Verify default values match OpenSSH behavior
	if cfg.Port != 22 {
		t.Errorf("Expected default port 22, got %d", cfg.Port)
	}

	if len(cfg.ListenAddress) != 1 || cfg.ListenAddress[0] != "0.0.0.0" {
		t.Errorf("Expected default listen address [0.0.0.0], got %v", cfg.ListenAddress)
	}

	if !cfg.PasswordAuthentication {
		t.Error("Expected PasswordAuthentication default to be true")
	}

	if !cfg.PubkeyAuthentication {
		t.Error("Expected PubkeyAuthentication default to be true")
	}

	if cfg.PermitRootLogin != "prohibit-password" {
		t.Errorf("Expected default PermitRootLogin 'prohibit-password', got %q", cfg.PermitRootLogin)
	}
}

func TestLoadBasicConfig(t *testing.T) {
	// Create temporary config file
	configContent := `# Test SSH config
Port 2222
ListenAddress 192.168.1.1
PasswordAuthentication no
PubkeyAuthentication yes
Subsystem sftp /usr/lib/openssh/sftp-server
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_sshd_config")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load the config
	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify parsed values
	if cfg.Port != 2222 {
		t.Errorf("Expected port 2222, got %d", cfg.Port)
	}

	if len(cfg.ListenAddress) < 2 || cfg.ListenAddress[1] != "192.168.1.1" {
		t.Errorf("Expected ListenAddress to include 192.168.1.1, got %v", cfg.ListenAddress)
	}

	if cfg.PasswordAuthentication {
		t.Error("Expected PasswordAuthentication to be false")
	}

	if !cfg.PubkeyAuthentication {
		t.Error("Expected PubkeyAuthentication to be true")
	}

	// Check subsystem was parsed
	sftpPath, ok := cfg.Subsystem["sftp"]
	if !ok {
		t.Error("Expected sftp subsystem to be defined")
	}
	if sftpPath != "/usr/lib/openssh/sftp-server" {
		t.Errorf("Expected sftp path '/usr/lib/openssh/sftp-server', got %q", sftpPath)
	}
}

func TestParseDirectiveErrors(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErr  bool
		errMatch string
	}{
		{
			name:     "invalid port number",
			content:  "Port abc",
			wantErr:  true,
			errMatch: "invalid port number",
		},
		{
			name:     "port out of range",
			content:  "Port 99999",
			wantErr:  true,
			errMatch: "invalid port number",
		},
		{
			name:     "missing port value",
			content:  "Port",
			wantErr:  true,
			errMatch: "port requires exactly one argument",
		},
		{
			name:     "incomplete subsystem",
			content:  "Subsystem sftp",
			wantErr:  true,
			errMatch: "subsystem requires exactly two arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "test_config")

			err := os.WriteFile(configFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			_, err = Load(configFile)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"yes", true},
		{"Yes", true},
		{"YES", true},
		{"true", true},
		{"True", true},
		{"1", true},
		{"no", false},
		{"No", false},
		{"false", false},
		{"0", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseBool(tt.input)
			if result != tt.expected {
				t.Errorf("parseBool(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLoadAuthorizationConfig(t *testing.T) {
	// Create temporary config file with authorization directives
	configContent := `# Test SSH authorization config
Port 2222
PermitRootLogin no
AllowUsers admin dev* @trusted.com
DenyUsers baduser evil*
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_sshd_config")

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load and parse configuration
	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify port
	if cfg.Port != 2222 {
		t.Errorf("Expected port 2222, got %d", cfg.Port)
	}

	// Verify PermitRootLogin
	if cfg.PermitRootLogin != "no" {
		t.Errorf("Expected PermitRootLogin 'no', got %q", cfg.PermitRootLogin)
	}

	// Verify AllowUsers
	expectedAllowUsers := []string{"admin", "dev*", "@trusted.com"}
	if len(cfg.AllowUsers) != len(expectedAllowUsers) {
		t.Errorf("Expected %d AllowUsers entries, got %d", len(expectedAllowUsers), len(cfg.AllowUsers))
	}
	for i, expected := range expectedAllowUsers {
		if i >= len(cfg.AllowUsers) || cfg.AllowUsers[i] != expected {
			t.Errorf("Expected AllowUsers[%d]=%q, got %q", i, expected, cfg.AllowUsers[i])
		}
	}

	// Verify DenyUsers
	expectedDenyUsers := []string{"baduser", "evil*"}
	if len(cfg.DenyUsers) != len(expectedDenyUsers) {
		t.Errorf("Expected %d DenyUsers entries, got %d", len(expectedDenyUsers), len(cfg.DenyUsers))
	}
	for i, expected := range expectedDenyUsers {
		if i >= len(cfg.DenyUsers) || cfg.DenyUsers[i] != expected {
			t.Errorf("Expected DenyUsers[%d]=%q, got %q", i, expected, cfg.DenyUsers[i])
		}
	}

	// Verify AuthorizedKeysFile
	expectedKeysFiles := []string{".ssh/authorized_keys", "/etc/ssh/keys/%u"}
	if len(cfg.AuthorizedKeysFile) != len(expectedKeysFiles) {
		t.Errorf("Expected %d AuthorizedKeysFile entries, got %d", len(expectedKeysFiles), len(cfg.AuthorizedKeysFile))
	}
	for i, expected := range expectedKeysFiles {
		if i >= len(cfg.AuthorizedKeysFile) || cfg.AuthorizedKeysFile[i] != expected {
			t.Errorf("Expected AuthorizedKeysFile[%d]=%q, got %q", i, expected, cfg.AuthorizedKeysFile[i])
		}
	}
}
