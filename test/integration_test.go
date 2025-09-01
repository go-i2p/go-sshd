package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSSHDBinaryBuild(t *testing.T) {
	// Test that the binary builds successfully
	cmd := exec.Command("go", "build", "-o", "test_sshd", "./cmd/sshd")
	cmd.Dir = ".."

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build sshd binary: %v\nOutput: %s", err, output)
	}

	// Clean up
	defer os.Remove("../test_sshd")

	// Test binary exists and is executable
	if _, err := os.Stat("../test_sshd"); os.IsNotExist(err) {
		t.Fatal("Binary was not created")
	}
}

func TestSSHDHelp(t *testing.T) {
	// Build the binary first
	buildCmd := exec.Command("go", "build", "-o", "test_sshd", "./cmd/sshd")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binary for help test: %v", err)
	}
	defer os.Remove("../test_sshd")

	// Test help output
	cmd := exec.Command("./test_sshd", "--help")
	cmd.Dir = ".."

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to run help command: %v", err)
	}

	helpText := string(output)

	// Verify key elements are in help text
	expectedStrings := []string{
		"sshd-go is a drop-in replacement",
		"Usage:",
		"--config",
		"--port",
		"--daemon",
		"--test",
		"--version",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(helpText, expected) {
			t.Errorf("Help text missing expected string: %q", expected)
		}
	}
}

func TestSSHDVersion(t *testing.T) {
	// Build the binary first
	buildCmd := exec.Command("go", "build", "-o", "test_sshd", "./cmd/sshd")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binary for version test: %v", err)
	}
	defer os.Remove("../test_sshd")

	// Test version output
	cmd := exec.Command("./test_sshd", "--version")
	cmd.Dir = ".."

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to run version command: %v", err)
	}

	versionText := string(output)

	// Should contain basic version info
	if !strings.Contains(versionText, "sshd-go") {
		t.Error("Version output should contain 'sshd-go'")
	}
}

func TestSSHDConfigTest(t *testing.T) {
	// Build the binary first
	buildCmd := exec.Command("go", "build", "-o", "test_sshd", "./cmd/sshd")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build binary for config test: %v", err)
	}
	defer os.Remove("../test_sshd")

	// Test config validation with non-existent config (should use defaults)
	cmd := exec.Command("./test_sshd", "--test", "--config", "/nonexistent")
	cmd.Dir = ".."

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Config test should not fail with non-existent config: %v", err)
	}

	configOutput := string(output)
	if !strings.Contains(configOutput, "Configuration file is valid") {
		t.Error("Expected 'Configuration file is valid' message")
	}
}
