package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-i2p/go-sshd/pkg/config"
)

func TestNewServer(t *testing.T) {
	cfg := &config.Config{
		Port:                   2222,
		HostKey:                []string{}, // Empty to avoid file system dependencies
		PasswordAuthentication: false,
		PubkeyAuthentication:   false,
		LogLevel:               "INFO",
		SyslogFacility:         "AUTH",
		LogFile:                "",
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}

	if server.config != cfg {
		t.Error("Server config not set correctly")
	}

	if server.ssh == nil {
		t.Error("SSH server not initialized")
	}

	if server.logger == nil {
		t.Error("Logger not initialized")
	}
}

func TestNewServerNilConfig(t *testing.T) {
	server, err := New(nil)
	if err == nil {
		t.Error("Expected error with nil config, got none")
	}

	if server != nil {
		t.Error("Expected nil server with nil config")
	}
}

func TestServerConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		port   int
		expect string
	}{
		{"default port", 22, ":22"},
		{"custom port", 2222, ":2222"},
		{"high port", 8022, ":8022"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Port:                   tt.port,
				HostKey:                []string{},
				PasswordAuthentication: false,
				PubkeyAuthentication:   false,
				LogLevel:               "INFO",
				SyslogFacility:         "AUTH",
				LogFile:                "",
			}

			server, err := New(cfg)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			if server.ssh.Addr != tt.expect {
				t.Errorf("Expected address %q, got %q", tt.expect, server.ssh.Addr)
			}
		})
	}
}

// TestServerLifecycle tests server creation and basic lifecycle
func TestServerLifecycle(t *testing.T) {
	cfg := &config.Config{
		Port:                   0, // Let system choose port for testing
		HostKey:                []string{},
		PasswordAuthentication: false,
		PubkeyAuthentication:   false,
		LogLevel:               "INFO",
		SyslogFacility:         "AUTH",
		LogFile:                "",
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test that server can be created without errors
	if server.ssh == nil {
		t.Error("SSH server not properly initialized")
	}

	// Test configuration is properly set
	if server.config.Port != 0 {
		t.Errorf("Expected port 0, got %d", server.config.Port)
	}

	// Note: We don't test Start() here as it would bind to a port
	// and block. Integration tests would handle actual server start/stop.
}

// Helper function to create a temporary config file
func createTempConfig(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "sshd_config")
	
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	
	return configFile
}

func TestNewWithConfigFile(t *testing.T) {
	configContent := `
Port 2223
PasswordAuthentication yes
PubkeyAuthentication no
LogLevel ERROR
`
	configFile := createTempConfig(t, configContent)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Override host keys to empty for testing (avoid file system dependencies)
	cfg.HostKey = []string{}

	server, err := NewWithConfigFile(cfg, configFile)
	if err != nil {
		t.Fatalf("Failed to create server with config file: %v", err)
	}
	defer server.Stop()

	if server.configFile != configFile {
		t.Errorf("Config file path not stored correctly: got %s, want %s", server.configFile, configFile)
	}

	if server.config.Port != 2223 {
		t.Errorf("Config not loaded correctly: got port %d, want 2223", server.config.Port)
	}

	if server.signalHandler == nil {
		t.Error("Signal handler not initialized")
	}
}

func TestSignalHandling(t *testing.T) {
	cfg := &config.Config{
		Port:                   0, // Use port 0 for testing
		HostKey:                []string{},
		PasswordAuthentication: false,
		PubkeyAuthentication:   false,
		LogLevel:               "ERROR",
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Test that signal handler context is available
	ctx := server.signalHandler.Context()
	if ctx == nil {
		t.Error("Signal handler context is nil")
	}

	// Test programmatic shutdown
	server.signalHandler.Shutdown()

	// Verify context is cancelled
	select {
	case <-ctx.Done():
		// Expected behavior
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after shutdown")
	}
}

func TestConfigurationReload(t *testing.T) {
	configContent := `
Port 2224
PasswordAuthentication yes
LogLevel INFO
`
	configFile := createTempConfig(t, configContent)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Override host keys to empty for testing (avoid file system dependencies)
	cfg.HostKey = []string{}

	server, err := NewWithConfigFile(cfg, configFile)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Verify initial config
	if server.config.LogLevel != "INFO" {
		t.Errorf("Initial log level incorrect: got %s, want INFO", server.config.LogLevel)
	}

	// Update config file
	newConfigContent := `
Port 2224
PasswordAuthentication yes
LogLevel DEBUG
`
	if err := os.WriteFile(configFile, []byte(newConfigContent), 0644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	// Test configuration reload
	if err := server.reloadConfiguration(); err != nil {
		t.Errorf("Failed to reload configuration: %v", err)
	}

	// Verify config was reloaded
	if server.config.LogLevel != "DEBUG" {
		t.Errorf("Log level not updated after reload: got %s, want DEBUG", server.config.LogLevel)
	}
}

func TestConfigurationReloadWithoutFile(t *testing.T) {
	cfg := &config.Config{
		Port:     2225,
		LogLevel: "INFO",
	}

	server, err := New(cfg) // No config file specified
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Test that reload fails when no config file is specified
	err = server.reloadConfiguration()
	if err == nil {
		t.Error("Expected error when reloading without config file")
	}

	expectedMsg := "no config file specified for reload"
	if err.Error() != expectedMsg {
		t.Errorf("Unexpected error message: got %s, want %s", err.Error(), expectedMsg)
	}
}

func TestServerStop(t *testing.T) {
	cfg := &config.Config{
		Port:     0,
		LogLevel: "ERROR",
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test that server can be stopped
	if err := server.Stop(); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}

	// Test that context is cancelled after stop
	select {
	case <-server.signalHandler.Context().Done():
		// Expected behavior
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled after stop")
	}
}
