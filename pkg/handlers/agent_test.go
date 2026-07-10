// Package handlers provides tests for SSH agent forwarding functionality.
package handlers

import (
	"context"
	"io"
	"net"
	"sync"
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

			ctx := newAgentMockContext("testuser", tt.permissions)

			result := handler.isAgentForwardingAllowed(ctx)
			assert.Equal(t, tt.expectAllow, result, tt.description)
		})
	}
}

// TestCreateAgentRequestHandler tests the agent forwarding request handler,
// including that approval records the request via ssh.SetAgentRequested so
// setupAgentForwarding (see shell.go) knows to provision SSH_AUTH_SOCK.
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

			ctx := newAgentMockContext("testuser", tt.permissions)
			req := &gossh.Request{
				Type:      "auth-agent-req@openssh.com",
				WantReply: true,
			}

			ok, payload := requestHandler(ctx, nil, req)

			assert.Equal(t, tt.expectOk, ok, tt.description)
			assert.Nil(t, payload) // Agent requests don't return payload
			assert.Equal(t, tt.expectOk, ssh.AgentRequested(newFakeSession(ctx)), "ssh.AgentRequested should reflect whether the request was approved")
		})
	}
}

// TestCreateAgentForwardingHandler_RejectsInboundChannel is a regression
// test for CRIT-3: registering a ChannelHandler for auth-agent@openssh.com
// used to wait to *receive* an inbound channel-open of that type from the
// client - a direction no standards-compliant client ever uses (the server
// is supposed to be the one opening these channels toward the client, via
// setupAgentForwarding/ssh.ForwardAgentConnections). The handler must now
// defensively reject any such inbound channel rather than servicing it.
func TestCreateAgentForwardingHandler_RejectsInboundChannel(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAgentHandler(&config.Config{AllowAgentForwarding: true}, logger)

	channelHandler := handler.CreateAgentForwardingHandler()
	require.NotNil(t, channelHandler)

	newCh := &fakeNewChannel{}
	ctx := newAgentMockContext("testuser", nil)

	channelHandler(nil, nil, newCh, ctx)

	assert.True(t, newCh.rejected, "inbound auth-agent@openssh.com channel-open must be rejected")
	assert.Equal(t, gossh.Prohibited, newCh.rejectReason)
}

// TestSetupAgentForwarding_NotRequested verifies that sessions which never
// requested agent forwarding get no SSH_AUTH_SOCK and a no-op cleanup.
func TestSetupAgentForwarding_NotRequested(t *testing.T) {
	ctx := newAgentMockContext("testuser", nil)
	sess := newFakeSession(ctx)

	sock, cleanup := setupAgentForwarding(sess, logrus.New())

	assert.Empty(t, sock)
	require.NotNil(t, cleanup)
	assert.NotPanics(t, cleanup)
}

// TestSetupAgentForwarding_Requested is a regression test for CRIT-3: once
// CreateAgentRequestHandler approves forwarding (recording it via
// ssh.SetAgentRequested), setupAgentForwarding must provision a real,
// connectable per-session Unix socket to expose as SSH_AUTH_SOCK, and the
// returned cleanup function must close it.
func TestSetupAgentForwarding_Requested(t *testing.T) {
	ctx := newAgentMockContext("testuser", nil)
	ctx.setValue(ssh.ContextKeyConn, &fakeGosshConn{})
	ssh.SetAgentRequested(ctx)
	sess := newFakeSession(ctx)

	sock, cleanup := setupAgentForwarding(sess, logrus.New())
	require.NotNil(t, cleanup)
	defer cleanup()

	require.NotEmpty(t, sock, "SSH_AUTH_SOCK path should be provisioned once agent forwarding was requested")

	// The returned path must be a live, connectable Unix socket.
	conn, err := net.DialTimeout("unix", sock, time.Second)
	require.NoError(t, err, "SSH_AUTH_SOCK path should be a connectable unix socket")
	_ = conn.Close()

	cleanup()
	_, err = net.DialTimeout("unix", sock, time.Second)
	assert.Error(t, err, "socket should be removed/closed after cleanup")
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

	ctx := newAgentMockContext("testuser", nil)
	req := &gossh.Request{Type: "auth-agent-req@openssh.com", WantReply: true}

	assert.NotPanics(t, func() {
		requestHandler(ctx, nil, req)
	})
}

// agentMockContext implements ssh.Context for testing agent functionality,
// with a real map-backed Value/SetValue so round-tripping through
// gliderlabs/ssh's own ssh.SetAgentRequested/ssh.AgentRequested (which use
// an unexported context key internal to that package) works correctly.
type agentMockContext struct {
	context.Context
	user        string
	permissions *ssh.Permissions
	mu          sync.Mutex
	values      map[interface{}]interface{}
}

func newAgentMockContext(user string, permissions *ssh.Permissions) *agentMockContext {
	return &agentMockContext{
		user:        user,
		permissions: permissions,
		values:      make(map[interface{}]interface{}),
	}
}

func (m *agentMockContext) setValue(key, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
}

func (m *agentMockContext) User() string          { return m.user }
func (m *agentMockContext) SessionID() string     { return "test-session" }
func (m *agentMockContext) ClientVersion() string { return "test-client" }
func (m *agentMockContext) ServerVersion() string { return "test-server" }
func (m *agentMockContext) RemoteAddr() net.Addr  { return &agentMockAddr{addr: "127.0.0.1:12345"} }

func (m *agentMockContext) LocalAddr() net.Addr           { return &agentMockAddr{addr: "127.0.0.1:22"} }
func (m *agentMockContext) Permissions() *ssh.Permissions { return m.permissions }

func (m *agentMockContext) SetValue(key, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
}

func (m *agentMockContext) Value(key interface{}) interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.values[key]
}

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

// fakeSession implements the (large) ssh.Session interface just enough to
// exercise setupAgentForwarding/ssh.AgentRequested in tests: only User,
// RemoteAddr, LocalAddr, and Context are meaningfully used by that code
// path, so the rest are unused stubs.
type fakeSession struct {
	ctx *agentMockContext
}

func newFakeSession(ctx *agentMockContext) *fakeSession {
	return &fakeSession{ctx: ctx}
}

func (s *fakeSession) Read(p []byte) (int, error)  { return 0, nil }
func (s *fakeSession) Write(p []byte) (int, error) { return len(p), nil }
func (s *fakeSession) Close() error                { return nil }
func (s *fakeSession) CloseWrite() error           { return nil }
func (s *fakeSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (s *fakeSession) Stderr() io.ReadWriter { return nil }

func (s *fakeSession) User() string             { return s.ctx.User() }
func (s *fakeSession) RemoteAddr() net.Addr     { return s.ctx.RemoteAddr() }
func (s *fakeSession) LocalAddr() net.Addr      { return s.ctx.LocalAddr() }
func (s *fakeSession) Environ() []string        { return nil }
func (s *fakeSession) Exit(code int) error      { return nil }
func (s *fakeSession) Command() []string        { return nil }
func (s *fakeSession) RawCommand() string       { return "" }
func (s *fakeSession) Subsystem() string        { return "" }
func (s *fakeSession) PublicKey() ssh.PublicKey { return nil }
func (s *fakeSession) Context() ssh.Context     { return s.ctx }
func (s *fakeSession) Permissions() ssh.Permissions {
	if s.ctx.permissions == nil {
		return ssh.Permissions{}
	}
	return *s.ctx.permissions
}
func (s *fakeSession) Pty() (ssh.Pty, <-chan ssh.Window, bool) { return ssh.Pty{}, nil, false }
func (s *fakeSession) Signals(c chan<- ssh.Signal)             {}
func (s *fakeSession) Break(c chan<- bool)                     {}

// fakeNewChannel implements gossh.NewChannel to verify
// CreateAgentForwardingHandler rejects inbound channels rather than
// accepting/servicing them.
type fakeNewChannel struct {
	rejected     bool
	rejectReason gossh.RejectionReason
}

func (c *fakeNewChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	return nil, nil, nil
}

func (c *fakeNewChannel) Reject(reason gossh.RejectionReason, message string) error {
	c.rejected = true
	c.rejectReason = reason
	return nil
}

func (c *fakeNewChannel) ChannelType() string { return "auth-agent@openssh.com" }
func (c *fakeNewChannel) ExtraData() []byte   { return nil }

// fakeGosshConn implements gossh.Conn with no-op methods, sufficient for
// ssh.ForwardAgentConnections to type-assert against and block on
// listener.Accept() without ever needing to actually open a channel in
// tests that don't push a connection through the forwarded socket.
type fakeGosshConn struct{}

func (c *fakeGosshConn) User() string          { return "testuser" }
func (c *fakeGosshConn) SessionID() []byte     { return nil }
func (c *fakeGosshConn) ClientVersion() []byte { return nil }
func (c *fakeGosshConn) ServerVersion() []byte { return nil }
func (c *fakeGosshConn) RemoteAddr() net.Addr  { return &agentMockAddr{addr: "127.0.0.1:12345"} }
func (c *fakeGosshConn) LocalAddr() net.Addr   { return &agentMockAddr{addr: "127.0.0.1:22"} }
func (c *fakeGosshConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, nil
}
func (c *fakeGosshConn) OpenChannel(name string, data []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	return nil, nil, nil
}
func (c *fakeGosshConn) Close() error { return nil }
func (c *fakeGosshConn) Wait() error  { return nil }
