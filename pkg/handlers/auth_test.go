package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// authMockContext implements ssh.Context for testing authentication.
// Supports SetValue/Value for storing authorized_keys options.
type authMockContext struct {
	context.Context
	user        string
	remoteAddr  net.Addr
	permissions *ssh.Permissions
	values      map[interface{}]interface{}
	mu          sync.Mutex
}

func newAuthMockContext(username string) *authMockContext {
	return &authMockContext{
		Context:    context.Background(),
		user:       username,
		remoteAddr: &authMockAddr{addr: "127.0.0.1:12345"},
		values:     make(map[interface{}]interface{}),
	}
}

func (m *authMockContext) User() string                  { return m.user }
func (m *authMockContext) SessionID() string             { return "test-session" }
func (m *authMockContext) ClientVersion() string         { return "test-client" }
func (m *authMockContext) ServerVersion() string         { return "test-server" }
func (m *authMockContext) RemoteAddr() net.Addr          { return m.remoteAddr }
func (m *authMockContext) LocalAddr() net.Addr           { return &authMockAddr{addr: "127.0.0.1:22"} }
func (m *authMockContext) Permissions() *ssh.Permissions { return m.permissions }
func (m *authMockContext) SetValue(key, value interface{}) {
	m.mu.Lock()
	m.values[key] = value
	m.mu.Unlock()
}

func (m *authMockContext) Value(key interface{}) interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.values[key]; ok {
		return v
	}
	return m.Context.Value(key)
}
func (m *authMockContext) Deadline() (deadline time.Time, ok bool) { return time.Time{}, false }
func (m *authMockContext) Done() <-chan struct{}                   { return nil }
func (m *authMockContext) Err() error                              { return nil }
func (m *authMockContext) Lock()                                   { m.mu.Lock() }
func (m *authMockContext) Unlock()                                 { m.mu.Unlock() }

// authMockAddr implements net.Addr for testing.
type authMockAddr struct {
	addr string
}

func (m *authMockAddr) Network() string { return "tcp" }
func (m *authMockAddr) String() string  { return m.addr }

// TestGetAuthorizedKeyOptionsFromContext tests context-based key options retrieval.
func TestGetAuthorizedKeyOptionsFromContext(t *testing.T) {
	t.Run("Returns nil when no options set", func(t *testing.T) {
		ctx := newAuthMockContext("testuser")
		opts := GetAuthorizedKeyOptionsFromContext(ctx)
		if opts != nil {
			t.Error("Expected nil options when none set in context")
		}
	})

	t.Run("Returns options when set in context", func(t *testing.T) {
		ctx := newAuthMockContext("testuser")
		expectedOpts := &AuthorizedKeyOptions{
			Command:          "/bin/backup",
			NoPortForwarding: true,
		}
		ctx.SetValue(ContextKeyAuthorizedKeyOptions, expectedOpts)

		opts := GetAuthorizedKeyOptionsFromContext(ctx)
		if opts == nil {
			t.Fatal("Expected options to be returned")
		}
		if opts.Command != "/bin/backup" {
			t.Errorf("Expected command '/bin/backup', got '%s'", opts.Command)
		}
		if !opts.NoPortForwarding {
			t.Error("Expected NoPortForwarding to be true")
		}
	})

	t.Run("Returns nil for wrong type in context", func(t *testing.T) {
		ctx := newAuthMockContext("testuser")
		ctx.SetValue(ContextKeyAuthorizedKeyOptions, "not-an-options-struct")

		opts := GetAuthorizedKeyOptionsFromContext(ctx)
		if opts != nil {
			t.Error("Expected nil when context contains wrong type")
		}
	})
}

func TestNewAuthHandler(t *testing.T) {
	cfg := &config.Config{
		PasswordAuthentication: true,
		PubkeyAuthentication:   true,
	}
	logger := logrus.New()
	logger.SetOutput(os.Stderr) // Prevent test output clutter

	handler := NewAuthHandler(cfg, logger)
	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}

	if handler.config != cfg {
		t.Error("Handler config not set correctly")
	}

	if handler.logger != logger {
		t.Error("Handler logger not set correctly")
	}

	if handler.authorizer == nil {
		t.Error("Handler authorizer not created")
	}
}

func TestCreatePasswordHandler_Disabled(t *testing.T) {
	cfg := &config.Config{
		PasswordAuthentication: false, // Disabled
		PubkeyAuthentication:   true,
	}
	logger, hook := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Test the handler creation - handler should still be created
	passwordHandler := handler.CreatePasswordHandler()
	if passwordHandler == nil {
		t.Error("Expected password handler to be created even when disabled")
	}

	// The handler should log that auth is disabled (we can't test the actual
	// authentication without a complex mock of ssh.Context)
	_ = hook // Avoid unused variable warning for now
}

func TestCreatePublicKeyHandler_Disabled(t *testing.T) {
	cfg := &config.Config{
		PasswordAuthentication: true,
		PubkeyAuthentication:   false, // Disabled
	}
	logger, hook := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Test the handler creation
	publicKeyHandler := handler.CreatePublicKeyHandler()
	if publicKeyHandler == nil {
		t.Error("Expected public key handler to be created even when disabled")
	}

	_ = hook // Avoid unused variable warning for now
}

func TestValidatePublicKey_NoUser(t *testing.T) {
	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Use non-existent user
	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	result := handler.validatePublicKey(newAuthMockContext("nonexistentuser123456"), "nonexistentuser123456", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected authentication to fail for non-existent user")
	}
}

func TestValidatePublicKey_WithTestKey(t *testing.T) {
	// Skip this test if we can't create temp files
	tmpDir := t.TempDir()

	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Generate test key pair
	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create a mock user with authorized_keys file
	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  tmpDir,
	}

	// Create authorized_keys file with our test key
	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))
	if err := os.WriteFile(authorizedKeysPath, []byte(keyData), 0o600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	// Test the key validation function directly
	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey, "127.0.0.1:12345")
	if !result {
		t.Error("Expected public key to be accepted from authorized_keys file")
	}
}

func TestValidatePublicKey_WrongKey(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Generate two different key pairs
	_, publicKey1, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key 1: %v", err)
	}

	_, publicKey2, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key 2: %v", err)
	}

	// Create mock user with authorized_keys containing key1
	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  tmpDir,
	}

	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey1))
	if err := os.WriteFile(authorizedKeysPath, []byte(keyData), 0o600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	// Try to authenticate with key2 (should fail)
	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey2, "127.0.0.1:12345")
	if result {
		t.Error("Expected public key authentication to fail with wrong key")
	}
}

func TestCheckAuthorizedKeysFile_NoFile(t *testing.T) {
	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  "/nonexistent",
	}

	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected authentication to fail when authorized_keys file doesn't exist")
	}
}

func TestCheckAuthorizedKeysFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  tmpDir,
	}

	// Create empty authorized_keys file
	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected authentication to fail with empty authorized_keys file")
	}
}

func TestCheckAuthorizedKeysFile_WithComments(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  tmpDir,
	}

	// Create authorized_keys with comments and empty lines
	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))
	content := `# This is a comment

# Another comment
` + keyData + `
# Final comment
`
	if err := os.WriteFile(authorizedKeysPath, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey, "127.0.0.1:12345")
	if !result {
		t.Error("Expected public key to be found despite comments and empty lines")
	}
}

// generateTestKeyPair creates an RSA key pair for testing
func generateTestKeyPair() (gossh.Signer, gossh.PublicKey, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Convert to SSH signer
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, signer.PublicKey(), nil
}

func TestAuthHandler_UserAuthorization(t *testing.T) {
	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
		AllowUsers:           []string{"alloweduser"},
		DenyUsers:            []string{"denieduser"},
		PermitRootLogin:      "no",
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Generate test key pair
	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Test denied user
	result := handler.validatePublicKey(newAuthMockContext("denieduser"), "denieduser", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected denieduser to be rejected by authorization")
	}

	// Test non-allowed user (when AllowUsers is specified)
	result = handler.validatePublicKey(newAuthMockContext("randomuser"), "randomuser", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected randomuser to be rejected when not in AllowUsers")
	}

	// Test root user (should be denied by PermitRootLogin=no)
	result = handler.validatePublicKey(newAuthMockContext("root"), "root", publicKey, "127.0.0.1:12345")
	if result {
		t.Error("Expected root to be rejected by PermitRootLogin=no")
	}
}

func TestCheckAuthorizedKeysFile_WithOptions(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		PubkeyAuthentication: true,
		AuthorizedKeysFile:   []string{".ssh/authorized_keys"},
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Generate test key pair
	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create mock user with authorized_keys file containing options
	mockUser := &user.User{
		Username: "testuser",
		HomeDir:  tmpDir,
	}

	// Create authorized_keys file with options
	sshDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))

	// Test with command restriction
	content := `command="/bin/backup",no-port-forwarding ` + keyData
	if err := os.WriteFile(authorizedKeysPath, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	ctx := newAuthMockContext("testuser")
	result := handler.checkAuthorizedKeysFile(ctx, mockUser, ".ssh/authorized_keys", publicKey, "127.0.0.1:12345")
	if !result {
		t.Error("Expected public key with options to be accepted")
	}

	// Verify that command restriction was stored in context
	storedOptions := ctx.Value(ContextKeyAuthorizedKeyOptions)
	if storedOptions == nil {
		t.Error("Expected authorized key options to be stored in context")
	} else {
		options, ok := storedOptions.(*AuthorizedKeyOptions)
		if !ok {
			t.Error("Stored options should be *AuthorizedKeyOptions type")
		} else if options.Command != "/bin/backup" {
			t.Errorf("Expected command '/bin/backup', got '%s'", options.Command)
		}
		if options.NoPortForwarding != true {
			t.Error("Expected NoPortForwarding to be true")
		}
	}
}

// TestCreateKeyboardInteractiveHandler_Disabled tests that keyboard-interactive auth respects config.
func TestCreateKeyboardInteractiveHandler_Disabled(t *testing.T) {
	cfg := &config.Config{
		PasswordAuthentication:       true,
		PubkeyAuthentication:         true,
		KbdInteractiveAuthentication: false, // Disabled
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Test the handler creation - handler should still be created
	kbdHandler := handler.CreateKeyboardInteractiveHandler()
	if kbdHandler == nil {
		t.Error("Expected keyboard-interactive handler to be created even when disabled")
	}

	// The handler would log that auth is disabled and return false
	// (we can't easily test the actual authentication without complex mocks)
}

// TestCreateKeyboardInteractiveHandler_Enabled tests that handler is created when enabled.
func TestCreateKeyboardInteractiveHandler_Enabled(t *testing.T) {
	cfg := &config.Config{
		PasswordAuthentication:       true,
		PubkeyAuthentication:         true,
		KbdInteractiveAuthentication: true, // Enabled
		AllowUsers:                   []string{},
		DenyUsers:                    []string{},
		PermitRootLogin:              "yes",
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Test the handler creation
	kbdHandler := handler.CreateKeyboardInteractiveHandler()
	if kbdHandler == nil {
		t.Error("Expected keyboard-interactive handler to be created when enabled")
	}
}

// TestAuthenticateKeyboardInteractive_MockChallenger tests the PAM conversation flow.
// Note: This test uses a mock challenger since we can't easily test actual PAM authentication
// without system-level PAM configuration and real user accounts.
func TestAuthenticateKeyboardInteractive_MockChallenger(t *testing.T) {
	cfg := &config.Config{
		KbdInteractiveAuthentication: true,
		AllowUsers:                   []string{},
		DenyUsers:                    []string{},
		PermitRootLogin:              "yes",
	}
	logger, _ := test.NewNullLogger()
	handler := NewAuthHandler(cfg, logger)

	// Create a mock challenger that simulates client responses
	mockChallenger := func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		// Return mock password for password prompt
		if len(questions) > 0 {
			answers := make([]string, len(questions))
			for i := range questions {
				if !echos[i] {
					// Password prompt
					answers[i] = "testpassword"
				} else {
					// Username or other prompt
					answers[i] = "testuser"
				}
			}
			return answers, nil
		}
		return []string{}, nil
	}

	// Note: This will attempt real PAM authentication with "testuser"
	// In most test environments, this will fail (which is expected)
	// We're primarily testing that the code doesn't panic and handles errors gracefully
	result := handler.authenticateKeyboardInteractive("testuser", mockChallenger)

	// We expect this to fail in test environment (no real PAM setup for testuser)
	// The important thing is no panic occurred
	if result {
		t.Log("Note: Keyboard-interactive auth succeeded (unexpected in test env)")
	}
}

// TestAuthenticateKeyboardInteractive_UserAuthorization tests user allow/deny lists.
func TestAuthenticateKeyboardInteractive_UserAuthorization(t *testing.T) {
	tests := []struct {
		name        string
		allowUsers  []string
		denyUsers   []string
		testUser    string
		expectAllow bool
	}{
		{
			name:        "Allow list permits user",
			allowUsers:  []string{"alice", "bob"},
			denyUsers:   []string{},
			testUser:    "alice",
			expectAllow: true,
		},
		{
			name:        "Allow list blocks user",
			allowUsers:  []string{"alice", "bob"},
			denyUsers:   []string{},
			testUser:    "charlie",
			expectAllow: false,
		},
		{
			name:        "Deny list blocks user",
			allowUsers:  []string{},
			denyUsers:   []string{"charlie"},
			testUser:    "charlie",
			expectAllow: false,
		},
		{
			name:        "Deny list permits user",
			allowUsers:  []string{},
			denyUsers:   []string{"charlie"},
			testUser:    "alice",
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				KbdInteractiveAuthentication: true,
				AllowUsers:                   tt.allowUsers,
				DenyUsers:                    tt.denyUsers,
				PermitRootLogin:              "yes",
			}
			logger, _ := test.NewNullLogger()
			handler := NewAuthHandler(cfg, logger)

			// Check authorization (before PAM is even attempted)
			allowed := handler.authorizer.IsUserAllowed(tt.testUser, "127.0.0.1:12345")
			if allowed != tt.expectAllow {
				t.Errorf("Expected IsUserAllowed=%v, got %v", tt.expectAllow, allowed)
			}
		})
	}
}

// TestAuthenticateKeyboardInteractive_RootLogin tests root login restrictions.
func TestAuthenticateKeyboardInteractive_RootLogin(t *testing.T) {
	tests := []struct {
		name            string
		permitRootLogin string
		authMethod      string
		expectAllow     bool
	}{
		{
			name:            "Root login yes allows keyboard-interactive",
			permitRootLogin: "yes",
			authMethod:      "keyboard-interactive",
			expectAllow:     true,
		},
		{
			name:            "Root login no blocks keyboard-interactive",
			permitRootLogin: "no",
			authMethod:      "keyboard-interactive",
			expectAllow:     false,
		},
		{
			name:            "Root login prohibit-password blocks keyboard-interactive",
			permitRootLogin: "prohibit-password",
			authMethod:      "keyboard-interactive",
			expectAllow:     false,
		},
		{
			name:            "Root login forced-commands-only blocks keyboard-interactive",
			permitRootLogin: "forced-commands-only",
			authMethod:      "keyboard-interactive",
			expectAllow:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				KbdInteractiveAuthentication: true,
				AllowUsers:                   []string{},
				DenyUsers:                    []string{},
				PermitRootLogin:              tt.permitRootLogin,
			}
			logger, _ := test.NewNullLogger()
			handler := NewAuthHandler(cfg, logger)

			// Check root login authorization
			allowed := handler.authorizer.IsRootLoginAllowed("root", tt.authMethod)
			if allowed != tt.expectAllow {
				t.Errorf("Expected IsRootLoginAllowed=%v for %s, got %v",
					tt.expectAllow, tt.permitRootLogin, allowed)
			}
		})
	}
}
