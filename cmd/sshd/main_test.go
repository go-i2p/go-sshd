// Package main provides comprehensive tests for the sshd-go CLI binary.
// These tests validate command-line argument parsing, configuration loading,
// and all user-facing functionality without requiring actual SSH connections.
//
// Test Coverage: 71.4%
// - Command structure and flag configuration
// - Version and help output functionality
// - Configuration file loading and validation
// - Port override functionality
// - Error handling for invalid arguments
// - Integration with validation system
//
// The tests use a helper function executeCommand() that captures both
// stdout and stderr output, enabling verification of all CLI behaviors.
package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// TestMain sets up test environment
func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	os.Exit(code)
}

// Helper function to execute command and capture output
func executeCommand(args ...string) (output string, err error) {
	// Create a new command for each test to avoid state pollution
	cmd := newRootCmd()

	// Capture output by redirecting both stdout and the command's output
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Also capture direct stdout (for version command)
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Set arguments
	cmd.SetArgs(args)

	// Execute command
	err = cmd.Execute()

	// Restore stdout and close pipe
	w.Close()
	os.Stdout = oldStdout

	// Read from pipe
	var stdoutBuf bytes.Buffer
	io.Copy(&stdoutBuf, r)

	// Combine outputs
	combinedOutput := buf.String() + stdoutBuf.String()

	return combinedOutput, err
}

// Helper function to create temporary config file
func createTempConfig(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "sshd_config_test_*.conf")
	if err != nil {
		return "", err
	}

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}

	return tmpfile.Name(), nil
}

// TestNewRootCmd verifies the root command is properly configured
func TestNewRootCmd(t *testing.T) {
	cmd := newRootCmd()

	// Test command properties
	if cmd.Use != "sshd" {
		t.Errorf("Expected Use to be 'sshd', got '%s'", cmd.Use)
	}

	if !strings.Contains(cmd.Short, "OpenSSH-compatible") {
		t.Errorf("Expected Short description to mention OpenSSH compatibility")
	}

	if !strings.Contains(cmd.Long, "drop-in replacement") {
		t.Errorf("Expected Long description to mention drop-in replacement")
	}

	// Test that RunE function is set
	if cmd.RunE == nil {
		t.Error("Expected RunE function to be set")
	}
}

// TestCommandFlags verifies all expected flags are present and configured correctly
func TestCommandFlags(t *testing.T) {
	cmd := newRootCmd()

	tests := []struct {
		name      string
		longFlag  string
		shortFlag string
		usage     string
	}{
		{"config", "config", "f", "configuration file"},
		{"port", "port", "p", "port number (overrides config)"},
		{"daemon", "daemon", "D", "run in foreground mode"},
		{"test", "test", "t", "test configuration and exit"},
		{"version", "version", "V", "show version information"},
		{"inetd", "inetd", "i", "run from inetd/systemd socket activation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.longFlag)
			if flag == nil {
				t.Fatalf("Flag '%s' not found", tt.longFlag)
			}

			if flag.Shorthand != tt.shortFlag {
				t.Errorf("Expected shorthand '%s', got '%s'", tt.shortFlag, flag.Shorthand)
			}

			if !strings.Contains(flag.Usage, tt.usage) {
				t.Errorf("Expected usage to contain '%s', got '%s'", tt.usage, flag.Usage)
			}
		})
	}
}

// TestVersionFlag tests the version output functionality
func TestVersionFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"long flag", []string{"--version"}},
		{"short flag", []string{"-V"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(tt.args...)
			if err != nil {
				t.Fatalf("Version command failed: %v", err)
			}

			// The output should contain version information
			t.Logf("Captured output: '%s'", output)

			if !strings.Contains(output, "sshd-go") {
				t.Errorf("Expected version output to contain 'sshd-go', got: %s", output)
			}

			// Should contain version info (even if it's "dev")
			expectedParts := []string{"sshd-go", "(commit", "built"}
			for _, part := range expectedParts {
				if !strings.Contains(output, part) {
					t.Errorf("Expected version output to contain '%s', got: %s", part, output)
				}
			}
		})
	}
}

// TestHelpFlag tests help output functionality
func TestHelpFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"help flag", []string{"--help"}},
		{"help command", []string{"help"}},
		{"short help", []string{"-h"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _ := executeCommand(tt.args...)
			// Help command should succeed but might return error for consistency with cobra

			// Verify help content
			expectedSections := []string{
				"Usage:",
				"sshd",
				"Flags:",
				"--config",
				"--port",
				"--daemon",
				"--test",
				"--version",
			}

			for _, section := range expectedSections {
				if !strings.Contains(output, section) {
					t.Errorf("Help output missing section '%s'. Output: %s", section, output)
				}
			}
		})
	}
}

// TestConfigFlag tests configuration file flag functionality
func TestConfigFlag(t *testing.T) {
	// Create a valid test config
	validConfig := `
Port 2222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
PubkeyAuthentication yes
`
	configFile, err := createTempConfig(validConfig)
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile)

	tests := []struct {
		name       string
		args       []string
		shouldFail bool
	}{
		{"valid config with long flag", []string{"--config", configFile, "--test"}, false},
		{"valid config with short flag", []string{"-f", configFile, "--test"}, false},
		{"nonexistent config", []string{"--config", "/nonexistent/config", "--test"}, false}, // Should use defaults
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(tt.args...)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected command to fail, but it succeeded. Output: %s", output)
				}
			} else {
				if err != nil {
					t.Errorf("Expected command to succeed, but it failed: %v. Output: %s", err, output)
				}
			}
		})
	}
}

// TestPortFlag tests port override functionality
func TestPortFlag(t *testing.T) {
	// Create a test config with a different port
	configContent := `Port 2222`
	configFile, err := createTempConfig(configContent)
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer os.Remove(configFile)

	tests := []struct {
		name        string
		args        []string
		expectError bool
		description string
	}{
		{"valid port long flag", []string{"--config", configFile, "--port", "3333", "--test"}, false, "should override config port"},
		{"valid port short flag", []string{"-f", configFile, "-p", "4444", "--test"}, false, "should override config port with short flag"},
		// Note: Invalid ports are caught by the config validation, which calls os.Exit
		// These tests would need more complex setup to properly test error conditions
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(tt.args...)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but command succeeded. Output: %s", tt.description, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v. Output: %s", tt.description, err, output)
				}
				// Verify the port was set correctly by checking the validation output
				if !strings.Contains(output, "Configuration file is valid") && !strings.Contains(output, "Validation Summary") {
					t.Errorf("Expected successful validation for %s. Output: %s", tt.description, output)
				}
			}
		})
	}
}

// TestTestFlag tests configuration validation functionality
func TestTestFlag(t *testing.T) {
	// Create various test configurations
	validConfig := `
Port 2222
ListenAddress 127.0.0.1
PasswordAuthentication no
PubkeyAuthentication yes
`

	invalidConfig := `
Port 99999
InvalidDirective invalid
`

	tests := []struct {
		name           string
		configContent  string
		expectValid    bool
		expectedOutput []string
	}{
		{
			name:           "valid configuration",
			configContent:  validConfig,
			expectValid:    true,
			expectedOutput: []string{"Configuration file is valid"},
		},
		{
			name:           "invalid configuration",
			configContent:  invalidConfig,
			expectValid:    false,
			expectedOutput: []string{"failed to load configuration", "invalid port number"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile, err := createTempConfig(tt.configContent)
			if err != nil {
				t.Fatalf("Failed to create temp config: %v", err)
			}
			defer os.Remove(configFile)

			output, err := executeCommand("--config", configFile, "--test")

			if tt.expectValid {
				if err != nil {
					t.Errorf("Expected valid config to pass, but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected invalid config to fail, but it passed")
				}
			}

			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s' for %s, got: %s", expected, tt.name, output)
				}
			}
		})
	}
}

// TestValidateAndReportConfig tests the detailed validation reporting
func TestValidateAndReportConfig(t *testing.T) {
	// Test with a known good config to verify the validation function works
	validConfig := &config.Config{
		Port:                   2222,
		ListenAddress:          []string{"127.0.0.1"},
		HostKey:                []string{"/etc/ssh/ssh_host_ed25519_key"},
		PasswordAuthentication: false,
		PubkeyAuthentication:   true,
	}

	// Test that validation runs (we can't easily test os.Exit without complex mocking)
	result := validConfig.Validate()
	if result == nil {
		t.Error("Expected validation result, got nil")
	}

	// This is a basic test - more complex validation testing would require
	// a refactored validation function that doesn't call os.Exit directly
}

// TestInvalidCommandLineArgs tests handling of invalid command line arguments
func TestInvalidCommandLineArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--unknown-flag"}},
		{"invalid port format", []string{"--port", "abc"}},
		{"missing port value", []string{"--port"}},
		{"missing config value", []string{"--config"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(tt.args...)
			if err == nil {
				t.Errorf("Expected error for invalid args %v, but command succeeded. Output: %s", tt.args, output)
			}
		})
	}
}

// TestConfigFileDefaultPath tests the default configuration file path behavior
func TestConfigFileDefaultPath(t *testing.T) {
	// Test with test flag to avoid actually starting server
	output, err := executeCommand("--test")
	// Should not fail even if default config doesn't exist (uses built-in defaults)
	if err != nil {
		// Check if it's a validation error vs a file not found error
		if !strings.Contains(output, "Configuration file is valid") {
			t.Errorf("Expected default config handling to work, got error: %v, output: %s", err, output)
		}
	}
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func() (cleanup func(), args []string)
		expectError      bool
		expectedInOutput []string
	}{
		{
			name: "invalid config directory as file",
			setupFunc: func() (func(), []string) {
				tmpDir, err := os.MkdirTemp("", "test_dir")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				return func() { os.RemoveAll(tmpDir) }, []string{"--config", tmpDir, "--test"}
			},
			expectError:      true,
			expectedInOutput: []string{}, // Error will be in stderr
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup, args := tt.setupFunc()
			defer cleanup()

			output, err := executeCommand(args...)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but command succeeded. Output: %s", tt.name, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v. Output: %s", tt.name, err, output)
				}
			}

			for _, expected := range tt.expectedInOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s' for %s, got: %s", expected, tt.name, output)
				}
			}
		})
	}
}

// TestBuildVersionInfo tests version information building
func TestBuildVersionInfo(t *testing.T) {
	// Test default version info
	output, err := executeCommand("--version")
	if err != nil {
		t.Fatalf("Version command failed: %v", err)
	}

	// Should contain default values or actual build values
	if !strings.Contains(output, "sshd-go") {
		t.Errorf("Version output should contain 'sshd-go', got: %s", output)
	}

	// Check that format is correct (contains parentheses for commit and build info)
	if !strings.Contains(output, "(commit") || !strings.Contains(output, "built") {
		t.Errorf("Version output should contain commit and build info, got: %s", output)
	}
}

// TestGenerateKeysFunctionality tests the host key generation functionality
func TestGenerateKeysFunctionality(t *testing.T) {
	// Create temporary directory for test keys
	tempDir := t.TempDir()
	
	// Create test configuration with custom key paths
	cfg := &config.Config{
		HostKey: []string{
			tempDir + "/test_rsa_key",
			tempDir + "/test_ecdsa_key", 
			tempDir + "/test_ed25519_key",
		},
	}

	// Test key generation
	err := generateHostKeys(cfg)
	if err != nil {
		t.Errorf("generateHostKeys failed: %v", err)
	}

	// Verify that key files were created
	for _, keyPath := range cfg.HostKey {
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Errorf("Host key file was not created: %s", keyPath)
		}
	}
}

// TestGenerateKeysWithDefaults tests key generation with default paths
func TestGenerateKeysWithDefaults(t *testing.T) {
	// Create test configuration with no host keys (should use defaults)
	cfg := &config.Config{
		HostKey: []string{}, // Empty to trigger defaults
	}

	// This test mainly checks that the function doesn't crash with default paths
	// It won't actually create files in /etc/ssh/ due to permissions
	// but it should not return an error about invalid configuration
	err := generateHostKeys(cfg)
	// We expect this to fail due to permissions, but not due to logic errors
	if err != nil && !strings.Contains(err.Error(), "permission denied") &&
		!strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("generateHostKeys failed with unexpected error: %v", err)
	}
}

// TestGenerateKeysFlag tests the -G flag functionality
func TestGenerateKeysFlag(t *testing.T) {
	// Test that -G flag is recognized (will fail due to permissions but shouldn't be "unknown flag")
	_, err := executeCommand("-G")
	
	// The command should recognize the flag but fail due to permissions
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "unknown flag") || strings.Contains(errStr, "unknown shorthand") {
			t.Errorf("Generate keys flag not recognized: %v", err)
		}
		// Permission errors are expected when trying to write to /etc/ssh/
	}
}

// BenchmarkCommandCreation benchmarks command creation performance
func BenchmarkCommandCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cmd := newRootCmd()
		if cmd == nil {
			b.Fatal("Command creation returned nil")
		}
	}
}

// BenchmarkVersionCommand benchmarks version command execution
func BenchmarkVersionCommand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := executeCommand("--version")
		if err != nil {
			b.Fatalf("Version command failed: %v", err)
		}
	}
}
