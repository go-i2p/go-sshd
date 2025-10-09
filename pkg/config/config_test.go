package config

import (
	"os"
	"path/filepath"
	"strings"
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

	// Verify logging defaults
	if cfg.LogLevel != "INFO" {
		t.Errorf("Expected default LogLevel INFO, got %s", cfg.LogLevel)
	}

	if cfg.SyslogFacility != "AUTH" {
		t.Errorf("Expected default SyslogFacility AUTH, got %s", cfg.SyslogFacility)
	}

	if cfg.LogFile != "" {
		t.Errorf("Expected default LogFile empty, got %s", cfg.LogFile)
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

	err := os.WriteFile(configFile, []byte(configContent), 0o644)
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

			err := os.WriteFile(configFile, []byte(tt.content), 0o644)
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

	err := os.WriteFile(configFile, []byte(configContent), 0o644)
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

func TestLoggingDirectives(t *testing.T) {
	// Create temporary config file with logging directives
	tmpDir, err := os.MkdirTemp("", "sshd-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configFile := filepath.Join(tmpDir, "sshd_config")
	configContent := `# Test logging directives
LogLevel DEBUG2
SyslogFacility LOCAL0
LogFile /var/log/sshd.log
Port 2222
`

	if err := os.WriteFile(configFile, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load and parse configuration
	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify logging settings
	if cfg.LogLevel != "DEBUG2" {
		t.Errorf("Expected LogLevel 'DEBUG2', got %q", cfg.LogLevel)
	}

	if cfg.SyslogFacility != "LOCAL0" {
		t.Errorf("Expected SyslogFacility 'LOCAL0', got %q", cfg.SyslogFacility)
	}

	if cfg.LogFile != "/var/log/sshd.log" {
		t.Errorf("Expected LogFile '/var/log/sshd.log', got %q", cfg.LogFile)
	}
}

func TestInvalidLoggingDirectives(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "invalid log level",
			content: "LogLevel INVALID\n",
			wantErr: true,
		},
		{
			name:    "invalid syslog facility",
			content: "SyslogFacility INVALID\n",
			wantErr: true,
		},
		{
			name:    "valid log levels",
			content: "LogLevel QUIET\nLogLevel FATAL\nLogLevel ERROR\nLogLevel INFO\nLogLevel VERBOSE\nLogLevel DEBUG\nLogLevel DEBUG1\nLogLevel DEBUG3\n",
			wantErr: false,
		},
		{
			name:    "valid syslog facilities",
			content: "SyslogFacility DAEMON\nSyslogFacility USER\nSyslogFacility AUTH\nSyslogFacility AUTHPRIV\nSyslogFacility LOCAL7\n",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "sshd-config-test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			configFile := filepath.Join(tmpDir, "sshd_config")
			if err := os.WriteFile(configFile, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			_, err = Load(configFile)
			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// Test comprehensive validation functionality

func TestValidationLevel_String(t *testing.T) {
	tests := []struct {
		level    ValidationLevel
		expected string
	}{
		{ValidationInfo, "INFO"},
		{ValidationWarning, "WARNING"},
		{ValidationError, "ERROR"},
		{ValidationLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("ValidationLevel(%d).String() = %q, want %q", int(tt.level), got, tt.expected)
		}
	}
}

func TestValidationResult_AddIssue(t *testing.T) {
	result := &ValidationResult{Valid: true}

	// Add an info issue
	result.AddIssue(ValidationInfo, "Port", "Test info", "")
	if result.InfoCount != 1 || len(result.Issues) != 1 || !result.Valid {
		t.Errorf("AddIssue(INFO) failed: info=%d, issues=%d, valid=%v", result.InfoCount, len(result.Issues), result.Valid)
	}

	// Add a warning issue
	result.AddIssue(ValidationWarning, "PasswordAuth", "Test warning", "Fix it")
	if result.WarnCount != 1 || len(result.Issues) != 2 || !result.Valid {
		t.Errorf("AddIssue(WARNING) failed: warn=%d, issues=%d, valid=%v", result.WarnCount, len(result.Issues), result.Valid)
	}

	// Add an error issue - should set Valid to false
	result.AddIssue(ValidationError, "HostKey", "Test error", "")
	if result.ErrorCount != 1 || len(result.Issues) != 3 || result.Valid {
		t.Errorf("AddIssue(ERROR) failed: error=%d, issues=%d, valid=%v", result.ErrorCount, len(result.Issues), result.Valid)
	}

	// Check issue details
	lastIssue := result.Issues[2]
	if lastIssue.Level != ValidationError || lastIssue.Directive != "HostKey" || lastIssue.Message != "Test error" {
		t.Errorf("Issue details incorrect: %+v", lastIssue)
	}
}

func TestConfig_ValidatePort(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		expectErrors int
		expectWarns  int
		expectInfos  int
	}{
		{"valid standard port", 22, 0, 1, 0},         // warning about privileged port
		{"valid high port", 8022, 0, 0, 1},           // info about non-standard port
		{"valid low privileged port", 1022, 0, 1, 1}, // warning about root + info about non-standard
		{"invalid zero port", 0, 1, 0, 0},
		{"invalid negative port", -1, 1, 0, 0},
		{"invalid high port", 70000, 1, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Port: tt.port}
			result := &ValidationResult{Valid: true}
			cfg.validatePort(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
				// Debug: print actual issues
				for _, issue := range result.Issues {
					t.Logf("Issue: %s - %s", issue.Level, issue.Message)
				}
			}
			if result.InfoCount != tt.expectInfos {
				t.Errorf("Expected %d infos, got %d", tt.expectInfos, result.InfoCount)
			}
		})
	}
}

func TestConfig_ValidateListenAddresses(t *testing.T) {
	tests := []struct {
		name         string
		addresses    []string
		expectErrors int
		expectWarns  int
		expectInfos  int
	}{
		{"valid specific IP", []string{"192.168.1.1"}, 0, 0, 0},
		{"all interfaces IPv4", []string{"0.0.0.0"}, 0, 0, 1}, // info about all interfaces
		{"all interfaces IPv6", []string{"::"}, 0, 0, 1},
		{"localhost", []string{"127.0.0.1"}, 0, 0, 0},
		{"valid hostname", []string{"localhost"}, 0, 0, 0},
		{"duplicate addresses", []string{"192.168.1.1", "192.168.1.1"}, 0, 1, 0},
		{"invalid IP", []string{"999.999.999.999"}, 1, 0, 0},
		{"invalid hostname", []string{"invalid..hostname"}, 1, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{ListenAddress: tt.addresses}
			result := &ValidationResult{Valid: true}
			cfg.validateListenAddresses(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
			if result.InfoCount != tt.expectInfos {
				t.Errorf("Expected %d infos, got %d", tt.expectInfos, result.InfoCount)
			}
		})
	}
}

func TestConfig_ValidateHostKeys(t *testing.T) {
	// Create temporary files for testing
	tmpDir := t.TempDir()
	existingKey := filepath.Join(tmpDir, "ssh_host_rsa_key")
	if err := os.WriteFile(existingKey, []byte("fake key"), 0o600); err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}

	tests := []struct {
		name         string
		hostKeys     []string
		expectErrors int
		expectWarns  int
		expectInfos  int
	}{
		{"no host keys", []string{}, 1, 0, 0},
		{"existing key", []string{existingKey}, 0, 0, 1}, // info about using modern keys
		{"non-existent key", []string{"/nonexistent/key"}, 0, 1, 1},
		{"multiple RSA keys", []string{
			filepath.Join(tmpDir, "ssh_host_rsa_key"),
			filepath.Join(tmpDir, "ssh_host_rsa_key2"),
		}, 0, 2, 1}, // warning about multiple same type + warning about non-existent + info about modern keys
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{HostKey: tt.hostKeys}
			result := &ValidationResult{Valid: true}
			cfg.validateHostKeys(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
			if result.InfoCount != tt.expectInfos {
				t.Errorf("Expected %d infos, got %d", tt.expectInfos, result.InfoCount)
			}
		})
	}
}

func TestConfig_ValidateAuthentication(t *testing.T) {
	tests := []struct {
		name               string
		passwordAuth       bool
		pubkeyAuth         bool
		authorizedKeysFile []string
		expectErrors       int
		expectWarns        int
	}{
		{"both auth methods", true, true, []string{".ssh/authorized_keys"}, 0, 1}, // warning about password auth
		{"only pubkey", false, true, []string{".ssh/authorized_keys"}, 0, 0},
		{"only password", true, false, []string{".ssh/authorized_keys"}, 0, 1},
		{"no auth methods", false, false, []string{".ssh/authorized_keys"}, 1, 0},
		{"dangerous authorized keys path", true, true, []string{"../../../etc/passwd"}, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				PasswordAuthentication: tt.passwordAuth,
				PubkeyAuthentication:   tt.pubkeyAuth,
				AuthorizedKeysFile:     tt.authorizedKeysFile,
			}
			result := &ValidationResult{Valid: true}
			cfg.validateAuthentication(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
		})
	}
}

func TestConfig_ValidateAuthorization(t *testing.T) {
	tests := []struct {
		name            string
		permitRootLogin string
		allowUsers      []string
		denyUsers       []string
		expectErrors    int
		expectWarns     int
	}{
		{"valid prohibit-password", "prohibit-password", []string{}, []string{}, 0, 0},
		{"dangerous root yes", "yes", []string{}, []string{}, 0, 1},
		{"invalid root login value", "maybe", []string{}, []string{}, 1, 0},
		{"conflicting user lists", "no", []string{"admin", "user"}, []string{"admin"}, 0, 1},
		{"separate user lists", "no", []string{"admin"}, []string{"guest"}, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				PermitRootLogin: tt.permitRootLogin,
				AllowUsers:      tt.allowUsers,
				DenyUsers:       tt.denyUsers,
			}
			result := &ValidationResult{Valid: true}
			cfg.validateAuthorization(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
		})
	}
}

func TestConfig_ValidateLogging(t *testing.T) {
	tmpDir := t.TempDir()
	validLogFile := filepath.Join(tmpDir, "test.log")

	tests := []struct {
		name         string
		logLevel     string
		logFile      string
		expectErrors int
		expectWarns  int
		expectInfos  int
	}{
		{"normal logging", "INFO", "", 0, 0, 0},
		{"debug logging", "DEBUG", "", 0, 0, 1}, // info about debug logging
		{"valid log file", "INFO", validLogFile, 0, 0, 0},
		{"invalid log dir", "INFO", "/nonexistent/dir/test.log", 1, 1, 0}, // error for missing dir + warning for can't write
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				LogLevel: tt.logLevel,
				LogFile:  tt.logFile,
			}
			result := &ValidationResult{Valid: true}
			cfg.validateLogging(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
			if result.InfoCount != tt.expectInfos {
				t.Errorf("Expected %d infos, got %d", tt.expectInfos, result.InfoCount)
			}
		})
	}
}

func TestConfig_ValidateSubsystems(t *testing.T) {
	tmpDir := t.TempDir()
	existingBinary := filepath.Join(tmpDir, "sftp-server")
	if err := os.WriteFile(existingBinary, []byte("fake binary"), 0o755); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	tests := []struct {
		name         string
		subsystems   map[string]string
		expectErrors int
		expectWarns  int
		expectInfos  int
	}{
		{"no subsystems", map[string]string{}, 0, 0, 1}, // info about missing SFTP
		{"valid SFTP", map[string]string{"sftp": existingBinary}, 0, 0, 0},
		{"non-existent binary", map[string]string{"sftp": "/nonexistent"}, 1, 1, 0}, // error for missing binary + warning if validateLogging tries to write
		{"suspicious SFTP path", map[string]string{"sftp": "/bin/cat"}, 0, 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Subsystem: tt.subsystems}
			result := &ValidationResult{Valid: true}
			cfg.validateSubsystems(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
			if result.InfoCount != tt.expectInfos {
				t.Errorf("Expected %d infos, got %d", tt.expectInfos, result.InfoCount)
			}
		})
	}
}

func TestConfig_ValidateCrossDependencies(t *testing.T) {
	tests := []struct {
		name            string
		passwordAuth    bool
		pubkeyAuth      bool
		permitRootLogin string
		allowUsers      []string
		expectErrors    int
		expectWarns     int
	}{
		{"secure config", false, true, "prohibit-password", []string{}, 0, 0},
		{"dangerous root+password", true, true, "yes", []string{}, 1, 0}, // error for root+password (only cross-dependencies, not auth warnings)
		{"auth disabled with restrictions", false, false, "no", []string{"admin"}, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				PasswordAuthentication: tt.passwordAuth,
				PubkeyAuthentication:   tt.pubkeyAuth,
				PermitRootLogin:        tt.permitRootLogin,
				AllowUsers:             tt.allowUsers,
			}
			result := &ValidationResult{Valid: true}
			cfg.validateCrossDependencies(result)

			if result.ErrorCount != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d", tt.expectErrors, result.ErrorCount)
			}
			if result.WarnCount != tt.expectWarns {
				t.Errorf("Expected %d warnings, got %d", tt.expectWarns, result.WarnCount)
			}
		})
	}
}

func TestConfig_Validate_Integration(t *testing.T) {
	// Test the full Validate method with a realistic configuration
	tmpDir := t.TempDir()
	hostKey := filepath.Join(tmpDir, "ssh_host_ed25519_key")
	if err := os.WriteFile(hostKey, []byte("fake key"), 0o600); err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	cfg := &Config{
		Port:                   2222,
		ListenAddress:          []string{"127.0.0.1"},
		HostKey:                []string{hostKey},
		PasswordAuthentication: false,
		PubkeyAuthentication:   true,
		PermitRootLogin:        "prohibit-password",
		AuthorizedKeysFile:     []string{".ssh/authorized_keys"},
		Subsystem:              map[string]string{},
		AllowTcpForwarding:     true,
		X11Forwarding:          false,
		GatewayPorts:           false,
		LogLevel:               "INFO",
		SyslogFacility:         "AUTH",
		LogFile:                "",
	}

	result := cfg.Validate()

	// Should be valid overall with some informational messages
	if !result.Valid {
		t.Errorf("Expected valid configuration, but got invalid with errors: %v", result.Issues)
	}

	// Should have some info messages (non-standard port, missing SFTP)
	if result.InfoCount < 1 {
		t.Errorf("Expected at least 1 info message, got %d", result.InfoCount)
	}

	// Should have no errors
	if result.ErrorCount > 0 {
		t.Errorf("Expected no errors, got %d", result.ErrorCount)
	}
}

func TestHelperFunctions(t *testing.T) {
	// Test isValidHostname
	hostnameTests := []struct {
		hostname string
		valid    bool
	}{
		{"localhost", true},
		{"example.com", true},
		{"test-host", true},
		{"192.168.1.1", false}, // IP addresses should be validated separately
		{"invalid..hostname", false},
		{"toolong" + strings.Repeat("a", 250), false},
		{"", false},
	}

	for _, tt := range hostnameTests {
		if got := isValidHostname(tt.hostname); got != tt.valid {
			t.Errorf("isValidHostname(%q) = %v, want %v", tt.hostname, got, tt.valid)
		}
	}

	// Test detectKeyType
	keyTypeTests := []struct {
		path     string
		expected string
	}{
		{"/etc/ssh/ssh_host_ed25519_key", "ed25519"},
		{"/etc/ssh/ssh_host_ecdsa_key", "ecdsa"},
		{"/etc/ssh/ssh_host_rsa_key", "rsa"},
		{"/etc/ssh/ssh_host_dsa_key", "dsa"},
		{"/etc/ssh/some_other_key", ""},
	}

	for _, tt := range keyTypeTests {
		if got := detectKeyType(tt.path); got != tt.expected {
			t.Errorf("detectKeyType(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestLoadMetricsConfig(t *testing.T) {
	// Test metrics configuration parsing
	configContent := `# Metrics configuration
MetricsEnabled yes
MetricsAddress 0.0.0.0:9090
`

	// Create temporary test config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_metrics_config")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load and parse config
	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify metrics settings
	if !cfg.MetricsEnabled {
		t.Error("Expected MetricsEnabled to be true")
	}

	if cfg.MetricsAddress != "0.0.0.0:9090" {
		t.Errorf("Expected MetricsAddress '0.0.0.0:9090', got %q", cfg.MetricsAddress)
	}
}

func TestMetricsConfigDefaults(t *testing.T) {
	// Test default metrics configuration
	cfg, err := Load("/nonexistent/config")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify defaults
	if cfg.MetricsEnabled {
		t.Error("Expected MetricsEnabled default to be false")
	}

	if cfg.MetricsAddress != "127.0.0.1:9100" {
		t.Errorf("Expected default MetricsAddress '127.0.0.1:9100', got %q", cfg.MetricsAddress)
	}
}

func TestInvalidMetricsAddress(t *testing.T) {
	// Test invalid metrics address
	configContent := `MetricsAddress invalid-address`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_invalid_metrics")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err := Load(configFile)
	if err == nil {
		t.Error("Expected error for invalid MetricsAddress format")
	}

	if !strings.Contains(err.Error(), "invalid metricsaddress format") {
		t.Errorf("Expected error about invalid metricsaddress format, got: %v", err)
	}
}
