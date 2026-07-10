// Package handlers provides tests for SSH port forwarding functionality.
package handlers

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// TestNewForwardingHandler tests the constructor for ForwardingHandler.
func TestNewForwardingHandler(t *testing.T) {
	cfg := &config.Config{
		AllowTcpForwarding: true,
		GatewayPorts:       false,
	}
	logger := logrus.New()

	handler := NewForwardingHandler(cfg, logger)

	require.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
	assert.NotNil(t, handler.tcpHandler)
}

// TestCreateLocalPortForwardHandler tests local port forwarding callback creation.
func TestCreateLocalPortForwardHandler(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		user        string
		host        string
		port        uint32
		expectAllow bool
	}{
		{
			name: "allow forwarding when enabled",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			host:        "127.0.0.1",
			port:        54321,
			expectAllow: true,
		},
		{
			name: "deny forwarding when disabled",
			config: &config.Config{
				AllowTcpForwarding: false,
			},
			user:        "testuser",
			host:        "127.0.0.1",
			port:        54321,
			expectAllow: false,
		},
		{
			name: "deny privileged port for non-root",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			host:        "127.0.0.1",
			port:        80,
			expectAllow: false,
		},
		{
			name: "allow privileged port for root",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "root",
			host:        "127.0.0.1",
			port:        80,
			expectAllow: true,
		},
		{
			name: "deny restricted metadata host",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			host:        "169.254.169.254",
			port:        80,
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewForwardingHandler(tt.config, logger)
			callback := handler.CreateLocalPortForwardHandler()

			// Create a mock context
			ctx := &mockContext{user: tt.user}
			result := callback(ctx, tt.host, tt.port)

			assert.Equal(t, tt.expectAllow, result)
		})
	}
}

// TestCreateReversePortForwardHandler tests reverse port forwarding callback creation.
func TestCreateReversePortForwardHandler(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		user        string
		host        string
		port        uint32
		expectAllow bool
	}{
		{
			name: "allow localhost binding",
			config: &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       false,
			},
			user:        "testuser",
			host:        "127.0.0.1",
			port:        54321,
			expectAllow: true,
		},
		{
			name: "deny all interfaces when gateway ports disabled",
			config: &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       false,
			},
			user:        "testuser",
			host:        "",
			port:        54321,
			expectAllow: false,
		},
		{
			name: "allow all interfaces when gateway ports enabled",
			config: &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       true,
			},
			user:        "testuser",
			host:        "",
			port:        54321,
			expectAllow: true,
		},
		{
			name: "allow specific IP when gateway ports enabled",
			config: &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       true,
			},
			user:        "testuser",
			host:        "192.168.1.100",
			port:        54321,
			expectAllow: true,
		},
		{
			name: "deny specific IP when gateway ports disabled",
			config: &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       false,
			},
			user:        "testuser",
			host:        "192.168.1.100",
			port:        54321,
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewForwardingHandler(tt.config, logger)
			callback := handler.CreateReversePortForwardHandler()

			// Create a mock context
			ctx := &mockContext{user: tt.user}
			result := callback(ctx, tt.host, tt.port)

			assert.Equal(t, tt.expectAllow, result)
		})
	}
}

// TestGetTCPHandler tests that the TCP handler is properly returned.
func TestGetTCPHandler(t *testing.T) {
	cfg := &config.Config{
		AllowTcpForwarding: true,
	}
	logger := logrus.New()
	handler := NewForwardingHandler(cfg, logger)

	tcpHandler := handler.GetTCPHandler()
	assert.NotNil(t, tcpHandler)
	assert.IsType(t, &ssh.ForwardedTCPHandler{}, tcpHandler)
}

// TestIsForwardingAllowed tests the forwarding permission logic.
func TestIsForwardingAllowed(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		user        string
		forwardType string
		host        string
		port        uint32
		expected    bool
	}{
		{
			name: "local forwarding allowed",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			forwardType: "local",
			host:        "example.com",
			port:        54321,
			expected:    true,
		},
		{
			name: "remote forwarding allowed",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			forwardType: "remote",
			host:        "example.com",
			port:        54321,
			expected:    true,
		},
		{
			name: "forwarding disabled",
			config: &config.Config{
				AllowTcpForwarding: false,
			},
			user:        "testuser",
			forwardType: "local",
			host:        "example.com",
			port:        54321,
			expected:    false,
		},
		{
			name: "invalid forward type",
			config: &config.Config{
				AllowTcpForwarding: true,
			},
			user:        "testuser",
			forwardType: "invalid",
			host:        "example.com",
			port:        54321,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewForwardingHandler(tt.config, logger)

			result := handler.isForwardingAllowed(tt.user, tt.forwardType, tt.host, tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsTargetHostAllowed tests the target host validation logic.
func TestIsTargetHostAllowed(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{
			name:     "localhost allowed",
			host:     "127.0.0.1",
			expected: true,
		},
		{
			name:     "localhost name allowed",
			host:     "localhost",
			expected: true,
		},
		{
			name:     "IPv6 localhost allowed",
			host:     "::1",
			expected: true,
		},
		{
			name:     "valid domain allowed",
			host:     "example.com",
			expected: true,
		},
		{
			name:     "AWS metadata blocked",
			host:     "169.254.169.254",
			expected: false,
		},
		{
			name:     "GCP metadata blocked",
			host:     "metadata.google.internal",
			expected: false,
		},
		{
			name:     "private IP allowed",
			host:     "192.168.1.1",
			expected: true,
		},
		{
			// Regression test: isAllowedIPOrDomain previously had a
			// tautological "|| true" that made this branch always allow any
			// public IP, defeating the loopback/private-only restriction.
			name:     "public IP not allowed",
			host:     "8.8.8.8",
			expected: false,
		},
		{
			// Regression test: ECS task metadata is served on a link-local
			// address (169.254.170.2) distinct from the well-known
			// 169.254.169.254; the old exact-match-only blocklist missed it.
			name:     "ECS task metadata blocked",
			host:     "169.254.170.2",
			expected: false,
		},
		{
			// Regression test: AWS IMDSv6 metadata service.
			name:     "AWS IMDSv6 metadata blocked",
			host:     "fd00:ec2::254",
			expected: false,
		},
		{
			name:     "IPv6 link-local blocked",
			host:     "fe80::1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				AllowTcpForwarding: true,
			}
			logger := logrus.New()
			handler := NewForwardingHandler(cfg, logger)

			result := handler.isTargetHostAllowed(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsRestrictedHost is a regression test for the metadata/link-local
// allow-list broadening: beyond the two originally hardcoded addresses,
// isRestrictedHost must now cover the whole link-local unicast range plus
// AWS's IPv6 metadata address.
func TestIsRestrictedHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{name: "AWS/Azure/GCP metadata IPv4", host: "169.254.169.254", expected: true},
		{name: "GCP metadata hostname", host: "metadata.google.internal", expected: true},
		{name: "AWS IMDSv6 metadata", host: "fd00:ec2::254", expected: true},
		{name: "ECS task metadata", host: "169.254.170.2", expected: true},
		{name: "arbitrary link-local IPv4", host: "169.254.1.1", expected: true},
		{name: "IPv6 link-local", host: "fe80::1", expected: true},
		{name: "private IPv4 not restricted", host: "192.168.1.1", expected: false},
		{name: "loopback not restricted", host: "127.0.0.1", expected: false},
		{name: "public IP not restricted", host: "8.8.8.8", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isRestrictedHost(tt.host))
		})
	}
}

// TestIsAllowedIPOrDomain is a direct regression test for the tautological
// "|| true" bug: isAllowedIPOrDomain must only allow loopback and private
// IPs (plus syntactically valid domain names), not arbitrary public IPs.
func TestIsAllowedIPOrDomain(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"loopback IPv4 allowed", "127.0.0.1", true},
		{"loopback IPv6 allowed", "::1", true},
		{"private IP allowed", "10.0.0.5", true},
		{"public IP not allowed", "8.8.8.8", false},
		{"other public IP not allowed", "1.1.1.1", false},
		{"domain name allowed", "example.com", true},
		{"empty host not allowed", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAllowedIPOrDomain(tt.host))
		})
	}
}

// TestIsBindAddressAllowed tests the bind address validation logic.
func TestIsBindAddressAllowed(t *testing.T) {
	tests := []struct {
		name         string
		gatewayPorts bool
		host         string
		expected     bool
	}{
		{
			name:         "localhost always allowed",
			gatewayPorts: false,
			host:         "127.0.0.1",
			expected:     true,
		},
		{
			name:         "localhost name always allowed",
			gatewayPorts: false,
			host:         "localhost",
			expected:     true,
		},
		{
			name:         "IPv6 localhost always allowed",
			gatewayPorts: false,
			host:         "::1",
			expected:     true,
		},
		{
			name:         "empty host denied when gateway ports disabled",
			gatewayPorts: false,
			host:         "",
			expected:     false,
		},
		{
			name:         "empty host allowed when gateway ports enabled",
			gatewayPorts: true,
			host:         "",
			expected:     true,
		},
		{
			name:         "wildcard denied when gateway ports disabled",
			gatewayPorts: false,
			host:         "*",
			expected:     false,
		},
		{
			name:         "wildcard allowed when gateway ports enabled",
			gatewayPorts: true,
			host:         "*",
			expected:     true,
		},
		{
			name:         "specific IP denied when gateway ports disabled",
			gatewayPorts: false,
			host:         "192.168.1.100",
			expected:     false,
		},
		{
			name:         "specific IP allowed when gateway ports enabled",
			gatewayPorts: true,
			host:         "192.168.1.100",
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				AllowTcpForwarding: true,
				GatewayPorts:       tt.gatewayPorts,
			}
			logger := logrus.New()
			handler := NewForwardingHandler(cfg, logger)

			result := handler.isBindAddressAllowed(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mockContext is a mock implementation of ssh.Context for testing.
type mockContext struct {
	context.Context
	user string
	mu   sync.Mutex
}

func (m *mockContext) User() string {
	return m.user
}

func (m *mockContext) SessionID() string {
	return "test-session"
}

func (m *mockContext) ClientVersion() string {
	return "test-client"
}

func (m *mockContext) ServerVersion() string {
	return "test-server"
}

func (m *mockContext) RemoteAddr() net.Addr {
	return &mockAddr{addr: "127.0.0.1:12345"}
}

func (m *mockContext) LocalAddr() net.Addr {
	return &mockAddr{addr: "127.0.0.1:22"}
}

func (m *mockContext) Permissions() *ssh.Permissions {
	return &ssh.Permissions{}
}

func (m *mockContext) SetValue(key, value interface{}) {
	// Mock implementation
}

func (m *mockContext) Value(key interface{}) interface{} {
	return nil
}

func (m *mockContext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (m *mockContext) Done() <-chan struct{} {
	return nil
}

func (m *mockContext) Err() error {
	return nil
}

func (m *mockContext) Lock() {
	m.mu.Lock()
}

func (m *mockContext) Unlock() {
	m.mu.Unlock()
}

// mockAddr is a mock implementation of net.Addr for testing.
type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string {
	return "tcp"
}

func (m *mockAddr) String() string {
	return m.addr
}
