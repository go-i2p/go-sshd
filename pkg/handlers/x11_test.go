// Package handlers provides tests for SSH X11 forwarding functionality.
package handlers

import (
	"context"
	"io"
	"net"
	"os"
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

// TestNewX11Handler tests the constructor for X11Handler.
func TestNewX11Handler(t *testing.T) {
	cfg := &config.Config{
		X11Forwarding:    true,
		X11DisplayOffset: 10,
		X11UseLocalhost:  true,
	}
	logger := logrus.New()

	handler := NewX11Handler(cfg, logger)

	require.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
	assert.NotNil(t, handler.displays)
}

// TestIsX11ForwardingAllowed tests the X11 forwarding permission logic.
func TestIsX11ForwardingAllowed(t *testing.T) {
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
				X11Forwarding: true,
			},
			permissions: nil,
			expectAllow: true,
			description: "Global configuration allows X11 forwarding",
		},
		{
			name: "deny when globally disabled",
			config: &config.Config{
				X11Forwarding: false,
			},
			permissions: nil,
			expectAllow: false,
			description: "Global configuration disables X11 forwarding",
		},
		{
			name: "deny when disabled by authorized key",
			config: &config.Config{
				X11Forwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"no-x11-forwarding": "true",
					},
				},
			},
			expectAllow: false,
			description: "Authorized key restriction overrides global setting",
		},
		{
			name: "allow when global enabled and no key restriction",
			config: &config.Config{
				X11Forwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"other-option": "value",
					},
				},
			},
			expectAllow: true,
			description: "No X11 forwarding restriction in authorized key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewX11Handler(tt.config, logger)

			// Create mock context
			ctx := &x11MockContext{
				user:        "testuser",
				permissions: tt.permissions,
			}

			result := handler.isX11ForwardingAllowed(ctx)
			assert.Equal(t, tt.expectAllow, result, tt.description)
		})
	}
}

// TestConnectToLocalX11 tests the X11 connection logic.
func TestConnectToLocalX11(t *testing.T) {
	logger := logrus.New()
	handler := NewX11Handler(&config.Config{}, logger)

	tests := []struct {
		name        string
		display     string
		expectError bool
		description string
	}{
		{
			name:        "fail when DISPLAY not set",
			display:     "",
			expectError: true,
			description: "Should fail when DISPLAY environment variable is not set",
		},
		{
			name:        "fail when X11 server unavailable",
			display:     ":999",
			expectError: true,
			description: "Should fail when X11 server socket does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for test
			t.Setenv("DISPLAY", tt.display)

			conn, err := handler.connectToLocalX11()

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

// TestGenerateX11Cookie tests X11 cookie generation.
func TestGenerateX11Cookie(t *testing.T) {
	cookie, err := GenerateX11Cookie()

	assert.NoError(t, err)
	assert.NotEmpty(t, cookie)
	// MIT-MAGIC-COOKIE-1 is 128 bits (16 bytes) = 32 hex characters
	assert.Equal(t, 32, len(cookie))

	// Generate another cookie to ensure they're different
	cookie2, err := GenerateX11Cookie()
	assert.NoError(t, err)
	assert.NotEqual(t, cookie, cookie2, "Cookies should be unique")
}

// TestParseDisplayNumber tests display number parsing.
func TestParseDisplayNumber(t *testing.T) {
	tests := []struct {
		name          string
		display       string
		expectHost    string
		expectDisplay int
		expectScreen  int
		expectError   bool
	}{
		{
			name:          "parse :0",
			display:       ":0",
			expectHost:    "",
			expectDisplay: 0,
			expectScreen:  0,
			expectError:   false,
		},
		{
			name:          "parse :10",
			display:       ":10",
			expectHost:    "",
			expectDisplay: 10,
			expectScreen:  0,
			expectError:   false,
		},
		{
			name:          "parse :0.0",
			display:       ":0.0",
			expectHost:    "",
			expectDisplay: 0,
			expectScreen:  0,
			expectError:   false,
		},
		{
			name:          "parse localhost:10",
			display:       "localhost:10",
			expectHost:    "localhost",
			expectDisplay: 10,
			expectScreen:  0,
			expectError:   false,
		},
		{
			name:          "parse localhost:10.1",
			display:       "localhost:10.1",
			expectHost:    "localhost",
			expectDisplay: 10,
			expectScreen:  1,
			expectError:   false,
		},
		{
			name:        "fail on empty display",
			display:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, displayNum, screenNum, err := ParseDisplayNumber(tt.display)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectHost, host)
				assert.Equal(t, tt.expectDisplay, displayNum)
				assert.Equal(t, tt.expectScreen, screenNum)
			}
		})
	}
}

// TestAllocateDisplay tests display allocation.
func TestAllocateDisplay(t *testing.T) {
	logger := logrus.New()
	config := &config.Config{
		X11DisplayOffset: 15,
	}
	handler := NewX11Handler(config, logger)

	// Allocate first display
	display1, cleanup1 := handler.AllocateDisplay("session1")
	assert.Equal(t, 15, display1, "First display should start at offset")

	// Allocate second display
	display2, cleanup2 := handler.AllocateDisplay("session2")
	assert.Equal(t, 16, display2, "Second display should be offset+1")

	// Verify displays are tracked
	handler.mu.Lock()
	assert.Equal(t, 2, len(handler.displays))
	handler.mu.Unlock()

	// Clean up first display
	cleanup1()
	handler.mu.Lock()
	assert.Equal(t, 1, len(handler.displays))
	_, exists := handler.displays["session1"]
	assert.False(t, exists)
	handler.mu.Unlock()

	// Clean up second display
	cleanup2()
	handler.mu.Lock()
	assert.Equal(t, 0, len(handler.displays))
	handler.mu.Unlock()
}

// TestCreateX11RequestHandler tests the X11 request handler.
func TestCreateX11RequestHandler(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		permissions *ssh.Permissions
		requestType string
		expectOk    bool
		description string
	}{
		{
			name: "approve x11-req when X11 forwarding allowed",
			config: &config.Config{
				X11Forwarding: true,
			},
			permissions: nil,
			requestType: "x11-req",
			expectOk:    true,
			description: "Should approve request when X11 forwarding is enabled",
		},
		{
			name: "deny x11-req when X11 forwarding disabled",
			config: &config.Config{
				X11Forwarding: false,
			},
			permissions: nil,
			requestType: "x11-req",
			expectOk:    false,
			description: "Should deny request when X11 forwarding is disabled",
		},
		{
			name: "deny x11-req when disabled by authorized key",
			config: &config.Config{
				X11Forwarding: true,
			},
			permissions: &ssh.Permissions{
				Permissions: &gossh.Permissions{
					Extensions: map[string]string{
						"no-x11-forwarding": "true",
					},
				},
			},
			requestType: "x11-req",
			expectOk:    false,
			description: "Should deny when restricted by authorized key options",
		},
		{
			name: "ignore non-x11-req requests",
			config: &config.Config{
				X11Forwarding: true,
			},
			permissions: nil,
			requestType: "other-request",
			expectOk:    false,
			description: "Should ignore non-X11 request types",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			handler := NewX11Handler(tt.config, logger)
			requestHandler := handler.CreateX11RequestHandler()

			// Create mock context and request
			ctx := &x11MockContext{
				user:        "testuser",
				permissions: tt.permissions,
			}
			req := &gossh.Request{
				Type:      tt.requestType,
				WantReply: true,
				Payload:   []byte{1}, // Minimal payload
			}

			ok, payload := requestHandler(ctx, nil, req)

			assert.Equal(t, tt.expectOk, ok, tt.description)
			assert.Nil(t, payload) // X11 requests don't return payload
		})
	}
}

// TestCreateX11ChannelHandler tests the X11 channel handler creation.
func TestCreateX11ChannelHandler(t *testing.T) {
	logger := logrus.New()
	config := &config.Config{
		X11Forwarding: true,
	}
	handler := NewX11Handler(config, logger)

	channelHandler := handler.CreateX11ChannelHandler()
	assert.NotNil(t, channelHandler)

	// Note: Full integration testing of the channel handler would require
	// complex mocking of the SSH session and X11 server socket.
	// This test verifies that the handler can be created successfully.
}

// TestX11HandlerErrorCases tests various error conditions.
func TestX11HandlerErrorCases(t *testing.T) {
	logger := logrus.New()

	t.Run("nil config", func(t *testing.T) {
		handler := NewX11Handler(nil, logger)
		assert.NotNil(t, handler)
		assert.Nil(t, handler.config)
	})

	t.Run("nil logger", func(t *testing.T) {
		config := &config.Config{X11Forwarding: true}
		handler := NewX11Handler(config, nil)
		assert.NotNil(t, handler)
		assert.Equal(t, config, handler.config)
		assert.Nil(t, handler.logger)
	})
}

// TestX11ConfigurationParsing tests X11 configuration directive parsing.
func TestX11ConfigurationParsing(t *testing.T) {
	tests := []struct {
		name               string
		configContent      string
		expectX11Forward   bool
		expectDisplayOff   int
		expectUseLocalhost bool
	}{
		{
			name: "default values",
			configContent: `
Port 22
`,
			expectX11Forward:   false,
			expectDisplayOff:   10,
			expectUseLocalhost: true,
		},
		{
			name: "X11 forwarding enabled",
			configContent: `
X11Forwarding yes
X11DisplayOffset 20
X11UseLocalhost no
`,
			expectX11Forward:   true,
			expectDisplayOff:   20,
			expectUseLocalhost: false,
		},
		{
			name: "X11 forwarding disabled",
			configContent: `
X11Forwarding no
`,
			expectX11Forward:   false,
			expectDisplayOff:   10,
			expectUseLocalhost: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpfile, err := os.CreateTemp("", "sshd_config_test_*.conf")
			require.NoError(t, err)
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.WriteString(tt.configContent)
			require.NoError(t, err)
			tmpfile.Close()

			// Parse configuration
			cfg, err := config.Load(tmpfile.Name())
			require.NoError(t, err)

			// Verify X11 settings
			assert.Equal(t, tt.expectX11Forward, cfg.X11Forwarding)
			assert.Equal(t, tt.expectDisplayOff, cfg.X11DisplayOffset)
			assert.Equal(t, tt.expectUseLocalhost, cfg.X11UseLocalhost)
		})
	}
}

// x11MockContext implements ssh.Context for testing X11 functionality.
type x11MockContext struct {
	context.Context
	user        string
	permissions *ssh.Permissions
	values      map[interface{}]interface{}
	mu          sync.Mutex
}

func (m *x11MockContext) User() string                  { return m.user }
func (m *x11MockContext) SessionID() string             { return "test-session-x11" }
func (m *x11MockContext) ClientVersion() string         { return "test-client" }
func (m *x11MockContext) ServerVersion() string         { return "test-server" }
func (m *x11MockContext) RemoteAddr() net.Addr          { return &x11MockAddr{addr: "127.0.0.1:12345"} }
func (m *x11MockContext) LocalAddr() net.Addr           { return &x11MockAddr{addr: "127.0.0.1:22"} }
func (m *x11MockContext) Permissions() *ssh.Permissions { return m.permissions }
func (m *x11MockContext) SetValue(key, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = make(map[interface{}]interface{})
	}
	m.values[key] = value
}

func (m *x11MockContext) Value(key interface{}) interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		return nil
	}
	return m.values[key]
}
func (m *x11MockContext) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (m *x11MockContext) Done() <-chan struct{}                   { return nil }
func (m *x11MockContext) Err() error                              { return nil }
func (m *x11MockContext) Lock()                                   { m.mu.Lock() }
func (m *x11MockContext) Unlock()                                 { m.mu.Unlock() }

// x11MockAddr implements net.Addr for testing.
type x11MockAddr struct {
	addr string
}

func (m *x11MockAddr) Network() string { return "tcp" }
func (m *x11MockAddr) String() string  { return m.addr }

// x11MockConn is a mock implementation of net.Conn for testing X11 data forwarding.
type x11MockConn struct {
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *x11MockConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *x11MockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *x11MockConn) Close() error {
	m.closed = true
	return nil
}

func (m *x11MockConn) LocalAddr() net.Addr                { return nil }
func (m *x11MockConn) RemoteAddr() net.Addr               { return nil }
func (m *x11MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *x11MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *x11MockConn) SetWriteDeadline(t time.Time) error { return nil }
