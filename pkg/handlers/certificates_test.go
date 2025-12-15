package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// Test helper: generate CA key pair for testing
func generateTestCAKey() (gossh.Signer, gossh.PublicKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, signer.PublicKey(), nil
}

// Test helper: generate user key pair for testing
func generateTestUserKey() (gossh.Signer, gossh.PublicKey, error) {
	return generateTestCAKey() // Same generation logic
}

// Test helper: create a test certificate
func createTestCertificate(t *testing.T, caSigner gossh.Signer, userPubKey gossh.PublicKey, principal string, validFor time.Duration) *gossh.Certificate {
	t.Helper()

	cert := &gossh.Certificate{
		Key:             userPubKey,
		Serial:          1,
		CertType:        gossh.UserCert,
		KeyId:           principal + "-key",
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-1 * time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(validFor).Unix()),
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("Failed to sign certificate: %v", err)
	}

	return cert
}

func TestNewCertificateValidator_NoConfig(t *testing.T) {
	cfg := &config.Config{
		TrustedUserCAKeys: []string{},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	if validator.IsCertificateAuthenticationEnabled() {
		t.Error("Expected certificate authentication to be disabled with no CA keys")
	}
}

func TestNewCertificateValidator_WithCAKeys(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test CA key
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	if !validator.IsCertificateAuthenticationEnabled() {
		t.Error("Expected certificate authentication to be enabled with CA keys")
	}

	// Verify CA key was loaded
	if len(validator.caKeys) != 1 {
		t.Errorf("Expected 1 CA key, got %d", len(validator.caKeys))
	}

	// Test that the CA key is recognized
	if !validator.isUserAuthority(caSigner.PublicKey()) {
		t.Error("CA key should be recognized as authority")
	}
}

func TestValidateCertificate_ValidCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA and user keys
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Create valid certificate
	cert := createTestCertificate(t, caSigner, userPubKey, "testuser", 1*time.Hour)

	// Validate certificate
	if err := validator.ValidateCertificate("testuser", cert); err != nil {
		t.Errorf("Expected valid certificate to pass validation: %v", err)
	}
}

func TestValidateCertificate_ExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA and user keys
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Create expired certificate (valid for negative duration = already expired)
	cert := createTestCertificate(t, caSigner, userPubKey, "testuser", -2*time.Hour)

	// Validate certificate - should fail due to expiry
	if err := validator.ValidateCertificate("testuser", cert); err == nil {
		t.Error("Expected expired certificate to fail validation")
	}
}

func TestValidateCertificate_WrongPrincipal(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA and user keys
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Create certificate for "alice" but try to use for "bob"
	cert := createTestCertificate(t, caSigner, userPubKey, "alice", 1*time.Hour)

	// Validate certificate with wrong username - should fail
	if err := validator.ValidateCertificate("bob", cert); err == nil {
		t.Error("Expected certificate with wrong principal to fail validation")
	}
}

func TestValidateCertificate_RevokedCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA and user keys
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	// Write revoked keys file
	revokedFile := filepath.Join(tmpDir, "revoked")
	revokedData := "1\n" // Revoke certificate with serial 1
	if err := os.WriteFile(revokedFile, []byte(revokedData), 0o600); err != nil {
		t.Fatalf("Failed to write revoked keys file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{revokedFile},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Create certificate with serial 1 (revoked)
	cert := createTestCertificate(t, caSigner, userPubKey, "testuser", 1*time.Hour)

	// Validate revoked certificate - should fail
	if err := validator.ValidateCertificate("testuser", cert); err == nil {
		t.Error("Expected revoked certificate to fail validation")
	}
}

func TestValidateCertificate_UntrustedCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate two CA keys
	_, trustedCAPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate trusted CA key: %v", err)
	}

	untrustedCASigner, _, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate untrusted CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write only trusted CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(trustedCAPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Create certificate signed by untrusted CA
	cert := createTestCertificate(t, untrustedCASigner, userPubKey, "testuser", 1*time.Hour)

	// Validate certificate - should fail due to untrusted CA
	if err := validator.ValidateCertificate("testuser", cert); err == nil {
		t.Error("Expected certificate from untrusted CA to fail validation")
	}
}

func TestValidateCertificate_NotACertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA key
	_, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Try to validate a regular public key (not a certificate)
	_, regularKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Should fail because it's not a certificate
	if err := validator.ValidateCertificate("testuser", regularKey); err == nil {
		t.Error("Expected non-certificate key to fail validation")
	}
}

func TestLoadCAKeyFile_MultipleKeys(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate multiple CA keys
	_, ca1PubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA1 key: %v", err)
	}

	_, ca2PubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA2 key: %v", err)
	}

	// Write multiple CA keys to same file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	content := string(gossh.MarshalAuthorizedKey(ca1PubKey)) +
		string(gossh.MarshalAuthorizedKey(ca2PubKey))
	if err := os.WriteFile(caKeyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Verify both CA keys were loaded
	if len(validator.caKeys) != 2 {
		t.Errorf("Expected 2 CA keys, got %d", len(validator.caKeys))
	}
}

func TestLoadRevokedKeyFile_MultipleSerials(t *testing.T) {
	tmpDir := t.TempDir()

	// Write revoked keys file with multiple serials
	revokedFile := filepath.Join(tmpDir, "revoked")
	revokedData := "1\n2\n3\n"
	if err := os.WriteFile(revokedFile, []byte(revokedData), 0o600); err != nil {
		t.Fatalf("Failed to write revoked keys file: %v", err)
	}

	// Also add a CA key file (required for initialization)
	_, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		TrustedUserCAKeys: []string{caKeyFile},
		RevokedKeys:       []string{revokedFile},
	}
	logger, _ := test.NewNullLogger()

	validator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected validator creation to succeed: %v", err)
	}

	// Verify all serials were loaded
	if len(validator.revokedSerials) != 3 {
		t.Errorf("Expected 3 revoked serials, got %d", len(validator.revokedSerials))
	}

	// Verify specific serials are revoked
	if !validator.revokedSerials[1] || !validator.revokedSerials[2] || !validator.revokedSerials[3] {
		t.Error("Expected serials 1, 2, 3 to be revoked")
	}
}

func TestCertificateIntegration_WithAuthHandler(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA and user keys
	caSigner, caPubKey, err := generateTestCAKey()
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	_, userPubKey, err := generateTestUserKey()
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	// Write CA public key to file
	caKeyFile := filepath.Join(tmpDir, "ca.pub")
	caKeyData := gossh.MarshalAuthorizedKey(caPubKey)
	if err := os.WriteFile(caKeyFile, caKeyData, 0o600); err != nil {
		t.Fatalf("Failed to write CA key file: %v", err)
	}

	cfg := &config.Config{
		PubkeyAuthentication: true,
		TrustedUserCAKeys:    []string{caKeyFile},
		RevokedKeys:          []string{},
		PermitRootLogin:      "yes",
		AllowUsers:           []string{},
		DenyUsers:            []string{},
	}
	logger, _ := test.NewNullLogger()

	// Create auth handler (which includes certificate validator)
	authHandler := NewAuthHandler(cfg, logger)

	if authHandler.certValidator == nil {
		t.Fatal("Expected cert validator to be initialized")
	}

	if !authHandler.certValidator.IsCertificateAuthenticationEnabled() {
		t.Error("Expected certificate authentication to be enabled")
	}

	// Create valid certificate
	cert := createTestCertificate(t, caSigner, userPubKey, "testuser", 1*time.Hour)

	// Verify certificate can be validated
	if err := authHandler.certValidator.ValidateCertificate("testuser", cert); err != nil {
		t.Errorf("Expected certificate to be valid: %v", err)
	}
}
