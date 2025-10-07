package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

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

	result := handler.validatePublicKey("nonexistentuser123456", publicKey)
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))
	if err := os.WriteFile(authorizedKeysPath, []byte(keyData), 0600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	// Test the key validation function directly
	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey)
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey1))
	if err := os.WriteFile(authorizedKeysPath, []byte(keyData), 0600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	// Try to authenticate with key2 (should fail)
	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey2)
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

	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey)
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, []byte(""), 0600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey)
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))
	content := `# This is a comment

# Another comment
` + keyData + `
# Final comment
`
	if err := os.WriteFile(authorizedKeysPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey)
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
	result := handler.validatePublicKey("denieduser", publicKey)
	if result {
		t.Error("Expected denieduser to be rejected by authorization")
	}

	// Test non-allowed user (when AllowUsers is specified)
	result = handler.validatePublicKey("randomuser", publicKey)
	if result {
		t.Error("Expected randomuser to be rejected when not in AllowUsers")
	}

	// Test root user (should be denied by PermitRootLogin=no)
	result = handler.validatePublicKey("root", publicKey)
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
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("Failed to create .ssh directory: %v", err)
	}

	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	keyData := string(gossh.MarshalAuthorizedKey(publicKey))
	
	// Test with command restriction
	content := `command="/bin/backup",no-port-forwarding ` + keyData
	if err := os.WriteFile(authorizedKeysPath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write authorized_keys file: %v", err)
	}

	result := handler.checkAuthorizedKeysFile(mockUser, ".ssh/authorized_keys", publicKey)
	if !result {
		t.Error("Expected public key with options to be accepted")
	}
}
