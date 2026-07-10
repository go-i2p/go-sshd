// Package handlers provides tests for SSH agent forwarding functionality.
package handlers

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// TestNewAgentHandler tests the constructor for AgentHandler.
func TestNewAgentHandler(t *testing.T) {
	cfg := &config.Config{
		AllowAgentForwarding: true,
	}
	logger := logrus.New()

	handler := NewAgentHandler(cfg, logger)

	require.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
}

// TestIsAgentForwardingAllowed tests the agent forwarding permission logic.
func TestIsAgentForwardingAllowed(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		permissions *ssh.Permissions
		expectAllow bool
		description string
	}{
		{
			name: "allow when globally enabled",
			config: &config.Config{
				AllowAgentForwarding: true,
			},
			permissions: nil,
			expectAllow: true,
			description: "Global configuration allows agent forwarding",
		},
		{
			name: "deny when globally disabled",
			config: &config.Config{
				AllowAgentForwarding: false,
			},
			permissions: nil,
			expectAllow: false,
			description: "Global configuration disables agent forwarding",
		},
		{
			name: "deny when disabled by authorized key",
			config: &config.Config{
				AllowAgentForwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"no-agent-forwarding": "true",
					},
				},
			},
			expectAllow: false,
			description: "Authorized key restriction overrides global setting",
		},
		{
			name: "allow when global enabled and no key restriction",
			config: &config.Config{
				AllowAgentForwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"other-option": "value",
					},
				},
			},
			expectAllow: true,
			description: "No agent forwarding restriction in authorized key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewAgentHandler(tt.config, logger)

			// Create mock context using existing mockContext from forwarding_test.go
			ctx := &agentMockContext{
				user:        "testuser",
				permissions: tt.permissions,
			}

			result := handler.isAgentForwardingAllowed(ctx)
			assert.Equal(t, tt.expectAllow, result, tt.description)
		})
	}
}

// TestConnectToLocalAgent tests the local agent connection logic.
func TestConnectToLocalAgent(t *testing.T) {
	logger := logrus.New()
	handler := NewAgentHandler(&config.Config{}, logger)

	tests := []struct {
		name        string
		authSock    string
		expectError bool
		description string
	}{
		{
			name:        "fail when SSH_AUTH_SOCK not set",
			authSock:    "",
			expectError: true,
			description: "Should fail when SSH_AUTH_SOCK environment variable is not set",
		},
		{
			name:        "fail when socket does not exist",
			authSock:    "/nonexistent/socket",
			expectError: true,
			description: "Should fail when SSH agent socket does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for test
			if tt.authSock != "" {
				t.Setenv("SSH_AUTH_SOCK", tt.authSock)
			} else {
				t.Setenv("SSH_AUTH_SOCK", "")
			}

			conn, err := handler.connectToLocalAgent()

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, conn)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, conn)
				if conn != nil {
					conn.Close()
				}
			}
		})
	}
}

// TestCopyData tests the data copying functionality.
func TestCopyData(t *testing.T) {
	logger := logrus.New()
	handler := NewAgentHandler(&config.Config{}, logger)

	testData := []byte("test data for copying")
	src := &agentMockConn{readData: testData}
	dst := &agentMockConn{}

	n, err := handler.copyData(dst, src, "test->direction", "testuser")

	assert.NoError(t, err)
	assert.Equal(t, int64(len(testData)), n)
	assert.Equal(t, testData, dst.writeData)
}

// TestCreateAgentRequestHandler tests the agent forwarding request handler.
func TestCreateAgentRequestHandler(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		permissions *ssh.Permissions
		expectOk    bool
		description string
	}{
		{
			name: "approve when agent forwarding allowed",
			config: &config.Config{
				AllowAgentForwarding: true,
			},
			permissions: nil,
			expectOk:    true,
			description: "Should approve request when agent forwarding is enabled",
		},
		{
			name: "deny when agent forwarding disabled",
			config: &config.Config{
				AllowAgentForwarding: false,
			},
			permissions: nil,
			expectOk:    false,
			description: "Should deny request when agent forwarding is disabled",
		},
		{
			name: "deny when disabled by authorized key",
			config: &config.Config{
				AllowAgentForwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"no-agent-forwarding": "true",
					},
				},
			},
			expectOk:    false,
			description: "Should deny when restricted by authorized key options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewAgentHandler(tt.config, logger)
			requestHandler := handler.CreateAgentRequestHandler()

			// Create mock context and request
			ctx := &agentMockContext{
				user:        "testuser",
				permissions: tt.permissions,
			}
			req := &gossh.Request{
				Type:      "auth-agent-req@openssh.com",
				WantReply: true,
			}

			ok, payload := requestHandler(ctx, nil, req)

			assert.Equal(t, tt.expectOk, ok, tt.description)
			assert.Nil(t, payload) // Agent requests don't return payload
		})
	}
}

// TestCreateAgentForwardingHandler tests the agent forwarding channel handler creation.
func TestCreateAgentForwardingHandler(t *testing.T) {
	logger := logrus.New()
	config := &config.Config{
		AllowAgentForwarding: true,
	}
	handler := NewAgentHandler(config, logger)

	channelHandler := handler.CreateAgentForwardingHandler()
	assert.NotNil(t, channelHandler)

	// Note: Full integration testing of the channel handler would require
	// more complex mocking of the SSH session and agent socket.
	// This test verifies that the handler can be created successfully.
}

// mockGosshChannel wraps a net.Conn (e.g. one side of a net.Pipe) to satisfy
// the gossh.Channel interface, so handleAgentChannel can be exercised with a
// real, concurrently-readable/writable connection instead of a hand-rolled
// buffer mock.
type mockGosshChannel struct {
	net.Conn
	closed atomic.Bool
}

func (c *mockGosshChannel) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *mockGosshChannel) CloseWrite() error { return nil }

func (c *mockGosshChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (c *mockGosshChannel) Stderr() io.ReadWriter { return nil }

// TestHandleAgentChannel_FullDuplexForwarding is a regression test for the
// premature-close bug: CreateAgentForwardingHandler used to defer-close the
// channel and agent connection in the outer closure, right after launching
// handleAgentChannel's copy goroutines, tearing down both connections before
// any data could be forwarded. This test exercises handleAgentChannel
// directly and proves bytes flow in both directions, and that the
// connections are only closed once forwarding actually ends.
func TestHandleAgentChannel_FullDuplexForwarding(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAgentHandler(&config.Config{}, logger)

	// channelConn/channelPeer simulates the SSH channel side of the proxy;
	// agentConn/agentPeer simulates the local SSH agent socket side.
	channelConn, channelPeer := net.Pipe()
	agentConn, agentPeer := net.Pipe()
	channel := &mockGosshChannel{Conn: channelConn}

	done := make(chan struct{})
	go func() {
		handler.handleAgentChannel(channel, agentConn, "testuser")
		close(done)
	}()

	// Client -> agent: bytes written on the channel peer must reach the
	// agent peer.
	clientMsg := []byte("client->agent request")
	go func() { _, _ = channelPeer.Write(clientMsg) }()
	gotFromClient := make([]byte, len(clientMsg))
	_, err := io.ReadFull(agentPeer, gotFromClient)
	require.NoError(t, err)
	assert.Equal(t, clientMsg, gotFromClient)

	// Agent -> client: bytes written on the agent peer must reach the
	// channel peer.
	agentMsg := []byte("agent->client response")
	go func() { _, _ = agentPeer.Write(agentMsg) }()
	gotFromAgent := make([]byte, len(agentMsg))
	_, err = io.ReadFull(channelPeer, gotFromAgent)
	require.NoError(t, err)
	assert.Equal(t, agentMsg, gotFromAgent)

	// Closing one peer ends the copy loop; handleAgentChannel must then
	// close both the channel and the agent connection itself.
	_ = channelPeer.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAgentChannel did not return after peer closed")
	}

	assert.True(t, channel.closed.Load(), "handleAgentChannel must close the channel when forwarding ends")
}

// TestAgentHandlerErrorCases tests various error conditions.
func TestAgentHandlerErrorCases(t *testing.T) {
	logger := logrus.New()

	t.Run("nil config", func(t *testing.T) {
		handler := NewAgentHandler(nil, logger)
		assert.NotNil(t, handler)
		assert.Nil(t, handler.config)
	})

	t.Run("nil logger", func(t *testing.T) {
		config := &config.Config{AllowAgentForwarding: true}
		handler := NewAgentHandler(config, nil)
		assert.NotNil(t, handler)
		assert.Equal(t, config, handler.config)
		assert.Nil(t, handler.logger)
	})
}

// TestCreateAgentRequestHandler_NilLoggerDoesNotPanic is a regression test
// for the nil-logger panic risk: AgentHandler's logging call sites must be
// nil-safe, matching the convention used by X11Handler and SFTPHandler.
func TestCreateAgentRequestHandler_NilLoggerDoesNotPanic(t *testing.T) {
	handler := NewAgentHandler(&config.Config{AllowAgentForwarding: true}, nil)
	requestHandler := handler.CreateAgentRequestHandler()

	ctx := &agentMockContext{user: "testuser"}
	req := &gossh.Request{Type: "auth-agent-req@openssh.com", WantReply: true}

	assert.NotPanics(t, func() {
		requestHandler(ctx, nil, req)
	})
}

// agentMockContext implements ssh.Context for testing agent functionality.
type agentMockContext struct {
	context.Context
	user        string
	permissions *ssh.Permissions
	mu          sync.Mutex
}

func (m *agentMockContext) User() string          { return m.user }
func (m *agentMockContext) SessionID() string     { return "test-session" }
func (m *agentMockContext) ClientVersion() string { return "test-client" }
func (m *agentMockContext) ServerVersion() string { return "test-server" }
func (m *agentMockContext) RemoteAddr() net.Addr  { return &agentMockAddr{addr: "127.0.0.1:12345"} }

func (m *agentMockContext) LocalAddr() net.Addr                     { return &agentMockAddr{addr: "127.0.0.1:22"} }
func (m *agentMockContext) Permissions() *ssh.Permissions           { return m.permissions }
func (m *agentMockContext) SetValue(key, value interface{})         {}
func (m *agentMockContext) Value(key interface{}) interface{}       { return nil }
func (m *agentMockContext) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (m *agentMockContext) Done() <-chan struct{}                   { return nil }
func (m *agentMockContext) Err() error                              { return nil }
func (m *agentMockContext) Lock()                                   { m.mu.Lock() }
func (m *agentMockContext) Unlock()                                 { m.mu.Unlock() }

// agentMockAddr implements net.Addr for testing.
type agentMockAddr struct {
	addr string
}

func (m *agentMockAddr) Network() string { return "tcp" }
func (m *agentMockAddr) String() string  { return m.addr }

// agentMockConn is a mock implementation of net.Conn for testing agent data copying.
type agentMockConn struct {
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *agentMockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *agentMockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *agentMockConn) Close() error {
	m.closed = true
	return nil
}

func (m *agentMockConn) LocalAddr() net.Addr                { return nil }
func (m *agentMockConn) RemoteAddr() net.Addr               { return nil }
func (m *agentMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *agentMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *agentMockConn) SetWriteDeadline(t time.Time) error { return nil }
