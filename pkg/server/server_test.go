package server

import (
	"testing"

	"github.com/go-i2p/go-sshd/pkg/config"
)

func TestNewServer(t *testing.T) {
	cfg := &config.Config{
		Port:                   2222,
		HostKey:                []string{}, // Empty to avoid file system dependencies
		PasswordAuthentication: false,
		PubkeyAuthentication:   false,
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
