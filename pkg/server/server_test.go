package server

import (
	"fmt"
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

	if err := os.WriteFile(configFile, []byte(content), 0o644); err != nil {
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
	// Reload now actually rebuilds the SSH server (including host keys) from
	// the config file, so point HostKey at a writable temp location instead
	// of the real /etc/ssh paths (which are not readable/writable in test
	// environments) to avoid a filesystem dependency.
	hostKeyPath := filepath.Join(t.TempDir(), "host_ed25519_key")
	configContent := fmt.Sprintf(`
Port 2224
PasswordAuthentication yes
LogLevel INFO
HostKey %s
`, hostKeyPath)
	configFile := createTempConfig(t, configContent)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

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
	newConfigContent := fmt.Sprintf(`
Port 2224
PasswordAuthentication yes
LogLevel DEBUG
HostKey %s
`, hostKeyPath)
	if err := os.WriteFile(configFile, []byte(newConfigContent), 0o644); err != nil {
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

// TestConfigurationReloadUpdatesRunningServer is a regression test for the
// SIGHUP-reload-has-no-effect bug: reloading configuration while the server
// is actively running must rebuild and swap in a new SSH server (not just
// update the config/logger struct fields), so that a subsequently changed
// policy (e.g. PasswordAuthentication) actually takes effect.
func TestConfigurationReloadUpdatesRunningServer(t *testing.T) {
	hostKeyPath := filepath.Join(t.TempDir(), "host_ed25519_key")
	configContent := fmt.Sprintf(`
Port 2227
PasswordAuthentication yes
LogLevel ERROR
HostKey %s
`, hostKeyPath)
	configFile := createTempConfig(t, configContent)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	server, err := NewWithConfigFile(cfg, configFile)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	firstSSH := server.getSSH()
	if firstSSH == nil {
		t.Fatal("Expected an initialized SSH server before reload")
	}

	newConfigContent := fmt.Sprintf(`
Port 2227
PasswordAuthentication no
LogLevel ERROR
HostKey %s
`, hostKeyPath)
	if err := os.WriteFile(configFile, []byte(newConfigContent), 0o644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	if err := server.reloadConfiguration(); err != nil {
		t.Fatalf("Failed to reload configuration: %v", err)
	}

	if server.config.PasswordAuthentication {
		t.Error("Expected PasswordAuthentication to be disabled after reload")
	}

	reloadedSSH := server.getSSH()
	if reloadedSSH == nil {
		t.Fatal("Expected a rebuilt SSH server after reload")
	}
	if reloadedSSH == firstSSH {
		t.Error("Expected reloadConfiguration to rebuild the SSH server instance, not reuse the old one")
	}
}

// TestConfigurationReloadWhileRunning exercises reloadConfiguration while the
// server is actively serving (Start running in the background), proving the
// listener-swap logic in runServerLoop correctly keeps the server alive
// across a reload instead of misinterpreting the old listener's shutdown as
// a fatal stop.
func TestConfigurationReloadWhileRunning(t *testing.T) {
	hostKeyPath := filepath.Join(t.TempDir(), "host_ed25519_key")
	configContent := fmt.Sprintf(`
Port 2228
PasswordAuthentication yes
LogLevel ERROR
HostKey %s
`, hostKeyPath)
	configFile := createTempConfig(t, configContent)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	cfg.Port = 0 // Use an ephemeral port for actual listening in this test.

	server, err := NewWithConfigFile(cfg, configFile)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- server.Start() }()

	// Give Start time to begin serving before reloading.
	time.Sleep(50 * time.Millisecond)

	newConfigContent := fmt.Sprintf(`
Port 2228
PasswordAuthentication no
LogLevel ERROR
HostKey %s
`, hostKeyPath)
	if err := os.WriteFile(configFile, []byte(newConfigContent), 0o644); err != nil {
		t.Fatalf("Failed to update config file: %v", err)
	}

	if err := server.reloadConfiguration(); err != nil {
		t.Fatalf("Failed to reload configuration while running: %v", err)
	}

	// The server must still be running after reload, not have exited.
	select {
	case err := <-startErr:
		t.Fatalf("Server unexpectedly stopped after reload: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: still running.
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	select {
	case err := <-startErr:
		if err != nil {
			t.Errorf("Start returned an error after Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
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

func TestMetricsServerIntegration(t *testing.T) {
	// Test that metrics server is created when enabled
	cfg := &config.Config{
		Port:           0, // Let system choose port
		LogLevel:       "ERROR",
		MetricsEnabled: true,
		MetricsAddress: "127.0.0.1:0", // Use port 0 to avoid conflicts
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Verify metrics collector was created
	if server.metricsCollector == nil {
		t.Error("Metrics collector should be created when MetricsEnabled is true")
	}

	// Verify metrics server was created
	if server.metricsServer == nil {
		t.Error("Metrics server should be created when MetricsEnabled is true")
	}
}

func TestMetricsServerDisabled(t *testing.T) {
	// Test that metrics server is NOT created when disabled
	cfg := &config.Config{
		Port:           0,
		LogLevel:       "ERROR",
		MetricsEnabled: false, // Explicitly disabled
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Stop()

	// Verify metrics collector was NOT created
	if server.metricsCollector != nil {
		t.Error("Metrics collector should be nil when MetricsEnabled is false")
	}

	// Verify metrics server was NOT created
	if server.metricsServer != nil {
		t.Error("Metrics server should be nil when MetricsEnabled is false")
	}
}

func TestMetricsServerStartStop(t *testing.T) {
	// Test that metrics server can be started and stopped
	cfg := &config.Config{
		Port:           0,
		LogLevel:       "ERROR",
		MetricsEnabled: true,
		MetricsAddress: "127.0.0.1:0", // Use port 0 to get random available port
	}

	server, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start the metrics server directly
	if err := server.metricsServer.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}

	// Stop the metrics server
	if err := server.metricsServer.Stop(); err != nil {
		t.Errorf("Failed to stop metrics server: %v", err)
	}

	// Clean up the rest
	server.Stop()
}
