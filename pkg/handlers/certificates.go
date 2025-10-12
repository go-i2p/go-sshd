// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This file implements SSH certificate validation using golang.org/x/crypto/ssh.
package handlers

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// CertificateValidator handles SSH certificate validation using golang.org/x/crypto/ssh.CertChecker.
// This is a thin wrapper around the standard library's certificate validation logic.
// Library-first approach: all certificate validation logic delegated to crypto/ssh.
type CertificateValidator struct {
	config         *config.Config
	logger         *logrus.Logger
	caKeys         map[string]gossh.PublicKey // Trusted CA keys indexed by fingerprint
	revokedSerials map[uint64]bool            // Revoked certificate serials
	certChecker    *gossh.CertChecker
}

// NewCertificateValidator creates a new certificate validator with CA keys and revocation list.
// Uses golang.org/x/crypto/ssh.CertChecker for all validation logic.
func NewCertificateValidator(cfg *config.Config, logger *logrus.Logger) (*CertificateValidator, error) {
	cv := &CertificateValidator{
		config:         cfg,
		logger:         logger,
		caKeys:         make(map[string]gossh.PublicKey),
		revokedSerials: make(map[uint64]bool),
	}

	// Load trusted CA keys
	if err := cv.loadTrustedCAKeys(); err != nil {
		return nil, fmt.Errorf("failed to load trusted CA keys: %w", err)
	}

	// Load revoked keys/certificates
	if err := cv.loadRevokedKeys(); err != nil {
		return nil, fmt.Errorf("failed to load revoked keys: %w", err)
	}

	// Create CertChecker with validation callbacks
	cv.certChecker = &gossh.CertChecker{
		IsUserAuthority: cv.isUserAuthority,
		IsRevoked:       cv.isRevoked,
		Clock:           time.Now, // Use real time for certificate validation
	}

	cv.logger.Infof("Certificate validator initialized with %d CA keys and %d revoked serials",
		len(cv.caKeys), len(cv.revokedSerials))

	return cv, nil
}

// ValidateCertificate validates an SSH certificate against trusted CAs and revocation list.
// This is a thin wrapper around gossh.CertChecker.CheckCert with manual CA signature verification.
// Returns nil if certificate is valid, error otherwise.
func (cv *CertificateValidator) ValidateCertificate(username string, key gossh.PublicKey) error {
	// Check if this is actually a certificate
	cert, ok := key.(*gossh.Certificate)
	if !ok {
		return fmt.Errorf("key is not a certificate")
	}

	// Log certificate details
	cv.logger.Debugf("Validating certificate for user %s: KeyId=%s, Serial=%d, Type=%d",
		username, cert.KeyId, cert.Serial, cert.CertType)

	// Validate certificate type (must be user cert)
	if cert.CertType != gossh.UserCert {
		cv.logger.Warnf("Certificate type mismatch for user %s: expected UserCert (1), got %d",
			username, cert.CertType)
		return fmt.Errorf("certificate is not a user certificate")
	}

	// First, verify the CA signature manually
	// CheckCert does NOT verify the signature - we must do this ourselves
	if !cv.isUserAuthority(cert.SignatureKey) {
		cv.logger.Warnf("Certificate for user %s signed by untrusted CA", username)
		return fmt.Errorf("certificate signed by untrusted CA")
	}

	// Use CertChecker to validate certificate
	// This checks: validity period, principals, critical options, revocation
	if err := cv.certChecker.CheckCert(username, cert); err != nil {
		cv.logger.Warnf("Certificate validation failed for user %s: %v", username, err)
		return err
	}

	cv.logger.Infof("Certificate validated successfully for user %s (KeyId: %s)",
		username, cert.KeyId)
	return nil
}

// loadTrustedCAKeys loads CA public keys from configured files.
// Each file can contain multiple keys (one per line) in authorized_keys format.
func (cv *CertificateValidator) loadTrustedCAKeys() error {
	if len(cv.config.TrustedUserCAKeys) == 0 {
		cv.logger.Debug("No TrustedUserCAKeys configured, certificate authentication disabled")
		return nil
	}

	for _, caKeyFile := range cv.config.TrustedUserCAKeys {
		if err := cv.loadCAKeyFile(caKeyFile); err != nil {
			return fmt.Errorf("failed to load CA key file %s: %w", caKeyFile, err)
		}
	}

	return nil
}

// loadCAKeyFile loads CA public keys from a single file.
func (cv *CertificateValidator) loadCAKeyFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		cv.logger.Warnf("Cannot open CA key file %s: %v", filename, err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse public key
		key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			cv.logger.Warnf("Failed to parse CA key at %s:%d: %v", filename, lineNum, err)
			continue
		}

		// Store CA key indexed by fingerprint
		fingerprint := gossh.FingerprintSHA256(key)
		cv.caKeys[fingerprint] = key
		cv.logger.Debugf("Loaded CA key from %s:%d (fingerprint: %s)", filename, lineNum, fingerprint)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading CA key file %s: %w", filename, err)
	}

	return nil
}

// loadRevokedKeys loads revoked certificate serials from configured files.
// Each file lists revoked keys in KRL (Key Revocation List) format or simple serial numbers.
func (cv *CertificateValidator) loadRevokedKeys() error {
	if len(cv.config.RevokedKeys) == 0 {
		cv.logger.Debug("No RevokedKeys configured, revocation checking disabled")
		return nil
	}

	for _, revokedFile := range cv.config.RevokedKeys {
		if err := cv.loadRevokedKeyFile(revokedFile); err != nil {
			// Log warning but don't fail - revocation is optional
			cv.logger.Warnf("Failed to load revoked keys file %s: %v", revokedFile, err)
		}
	}

	return nil
}

// loadRevokedKeyFile loads revoked certificate serials from a single file.
// For simplicity, we support a basic format: one serial number per line.
// Full KRL support would require additional parsing logic (future enhancement).
func (cv *CertificateValidator) loadRevokedKeyFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse serial number (simple format: one serial per line)
		var serial uint64
		if _, err := fmt.Sscanf(line, "%d", &serial); err != nil {
			cv.logger.Warnf("Failed to parse revoked serial at %s:%d: %v", filename, lineNum, err)
			continue
		}

		cv.revokedSerials[serial] = true
		cv.logger.Debugf("Loaded revoked serial from %s:%d: %d", filename, lineNum, serial)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading revoked keys file %s: %w", filename, err)
	}

	return nil
}

// isUserAuthority checks if a public key is a trusted CA for user certificates.
// This callback is used by gossh.CertChecker during certificate validation.
func (cv *CertificateValidator) isUserAuthority(auth gossh.PublicKey) bool {
	fingerprint := gossh.FingerprintSHA256(auth)
	_, trusted := cv.caKeys[fingerprint]
	
	if trusted {
		cv.logger.Debugf("CA key recognized: %s", fingerprint)
	} else {
		cv.logger.Debugf("CA key not trusted: %s", fingerprint)
	}
	
	return trusted
}

// isRevoked checks if a certificate has been revoked.
// This callback is used by gossh.CertChecker during certificate validation.
func (cv *CertificateValidator) isRevoked(cert *gossh.Certificate) bool {
	revoked := cv.revokedSerials[cert.Serial]
	
	if revoked {
		cv.logger.Warnf("Certificate serial %d is revoked (KeyId: %s)", cert.Serial, cert.KeyId)
	}
	
	return revoked
}

// IsCertificateAuthenticationEnabled returns true if certificate authentication is configured.
func (cv *CertificateValidator) IsCertificateAuthenticationEnabled() bool {
	return len(cv.caKeys) > 0
}
