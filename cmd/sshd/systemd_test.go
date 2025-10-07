package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSystemdServiceFiles tests that all systemd service files are present and valid
func TestSystemdServiceFiles(t *testing.T) {
	systemdDir := "../../systemd"

	requiredFiles := []string{
		"sshd-go.service",
		"sshd-go.socket",
		"sshd-go@.service",
		"sshd-go-keygen.service",
		"sshd-go.default",
	}

	for _, file := range requiredFiles {
		path := filepath.Join(systemdDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Required systemd file missing: %s", path)
		}
	}
}

// TestSystemdServiceConfiguration validates the content of systemd service files
func TestSystemdServiceConfiguration(t *testing.T) {
	// Test main service file
	serviceContent, err := os.ReadFile("../../systemd/sshd-go.service")
	if err != nil {
		t.Fatalf("Failed to read sshd-go.service: %v", err)
	}

	content := string(serviceContent)

	// Check for required sections and directives
	requiredStrings := []string{
		"[Unit]",
		"[Service]",
		"[Install]",
		"Type=notify",
		"ExecStart=/usr/local/sbin/sshd-go",
		"ExecReload=/bin/kill -HUP $MAINPID",
		"WantedBy=multi-user.target",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	}

	for _, required := range requiredStrings {
		if !containsString(content, required) {
			t.Errorf("sshd-go.service missing required content: %s", required)
		}
	}
}

// TestSocketConfiguration validates the socket activation configuration
func TestSocketConfiguration(t *testing.T) {
	socketContent, err := os.ReadFile("../../systemd/sshd-go.socket")
	if err != nil {
		t.Fatalf("Failed to read sshd-go.socket: %v", err)
	}

	content := string(socketContent)

	requiredStrings := []string{
		"[Unit]",
		"[Socket]",
		"[Install]",
		"ListenStream=22",
		"Accept=yes",
		"WantedBy=sockets.target",
		"Conflicts=sshd-go.service",
	}

	for _, required := range requiredStrings {
		if !containsString(content, required) {
			t.Errorf("sshd-go.socket missing required content: %s", required)
		}
	}
}

// TestInstallationScript tests the installation script existence and basic structure
func TestInstallationScript(t *testing.T) {
	scriptPath := "../../install.sh"

	// Check if script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Fatalf("Installation script missing: %s", scriptPath)
	}

	// Check if script is executable
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("Failed to stat install.sh: %v", err)
	}

	mode := info.Mode()
	if mode&0o111 == 0 {
		t.Error("Installation script is not executable")
	}

	// Read script content and check for basic structure
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read install.sh: %v", err)
	}

	content := string(scriptContent)

	requiredStrings := []string{
		"#!/bin/bash",
		"install_binary()",
		"install_systemd_files()",
		"configure_systemd()",
		"systemctl daemon-reload",
	}

	for _, required := range requiredStrings {
		if !containsString(content, required) {
			t.Errorf("install.sh missing required content: %s", required)
		}
	}
}

// TestInetdModeFlag tests that the -i flag is properly implemented
func TestInetdModeFlag(t *testing.T) {
	// This is a basic test to ensure the flag exists
	// More comprehensive testing would require integration tests

	// Test that the binary accepts the -i flag without error
	// This would be better tested with actual command execution in integration tests

	// For now, just verify the binary compiles with inetd support
	if _, err := os.Stat("../../sshd"); os.IsNotExist(err) {
		t.Skip("Binary not built, skipping inetd flag test")
	}

	// Additional testing would involve:
	// 1. Testing that -i flag is recognized
	// 2. Testing socket activation simulation
	// 3. Testing stdin/stdout connection handling
	// These are better suited for integration tests
}

// TestKeyGenService validates the key generation service configuration
func TestKeyGenService(t *testing.T) {
	keygenContent, err := os.ReadFile("../../systemd/sshd-go-keygen.service")
	if err != nil {
		t.Fatalf("Failed to read sshd-go-keygen.service: %v", err)
	}

	content := string(keygenContent)

	requiredStrings := []string{
		"[Unit]",
		"[Service]",
		"Type=oneshot",
		"ExecStart=/usr/local/sbin/sshd-go -G", // Should use -G flag, not -t
		"ConditionFileNotEmpty=|!/etc/ssh/ssh_host_rsa_key",
		"ConditionFileNotEmpty=|!/etc/ssh/ssh_host_ecdsa_key",
		"ConditionFileNotEmpty=|!/etc/ssh/ssh_host_ed25519_key",
	}

	for _, required := range requiredStrings {
		if !containsString(content, required) {
			t.Errorf("sshd-go-keygen.service missing required content: %s", required)
		}
	}

	// Ensure it's NOT using the -t flag (which only tests config)
	if containsString(content, "ExecStart=/usr/local/sbin/sshd-go -t") {
		t.Error("sshd-go-keygen.service should use -G flag, not -t flag for key generation")
	}
}
func containsString(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) &&
		(s == substr || s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr))
}

// findSubstring searches for substring within string
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
