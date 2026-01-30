// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/msteinert/pam"
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// ContextKeyAuthorizedKeyOptions is a context key for storing authorized_keys options.
// The associated value will be of type *AuthorizedKeyOptions.
const ContextKeyAuthorizedKeyOptions = "authorized-key-options"

// GetAuthorizedKeyOptions retrieves the authorized_keys options from a session context.
// Returns nil if no options are set (e.g., password authentication or key without options).
func GetAuthorizedKeyOptions(s ssh.Session) *AuthorizedKeyOptions {
	val := s.Context().Value(ContextKeyAuthorizedKeyOptions)
	if val == nil {
		return nil
	}
	if opts, ok := val.(*AuthorizedKeyOptions); ok {
		return opts
	}
	return nil
}

// AuthHandler handles SSH authentication using system libraries.
// This is a thin wrapper around msteinert/pam and crypto/ssh for OpenSSH compatibility.
type AuthHandler struct {
	config        *config.Config
	logger        *logrus.Logger
	authorizer    *UserAuthorizer
	certValidator *CertificateValidator
}

// NewAuthHandler creates a new authentication handler with the given configuration.
// Uses library-first approach - delegates all auth logic to mature libraries.
func NewAuthHandler(cfg *config.Config, logger *logrus.Logger) *AuthHandler {
	// Initialize certificate validator (may be nil if no CAs configured)
	certValidator, err := NewCertificateValidator(cfg, logger)
	if err != nil {
		logger.Warnf("Certificate validator initialization failed: %v", err)
		certValidator = nil // Continue without certificate support
	}

	return &AuthHandler{
		config:        cfg,
		logger:        logger,
		authorizer:    NewUserAuthorizer(cfg, logger),
		certValidator: certValidator,
	}
}

// CreatePasswordHandler creates an SSH password authentication handler.
// Uses msteinert/pam for system authentication integration.
func (a *AuthHandler) CreatePasswordHandler() ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		user := ctx.User()

		// Check if password authentication is enabled
		if !a.config.PasswordAuthentication {
			a.logger.Debugf("Password authentication disabled, rejecting user %s", user)
			return false
		}

		a.logger.Infof("Password authentication attempt for user %s from %s", user, ctx.RemoteAddr())

		// Check user authorization first (before expensive auth operations)
		if !a.authorizer.IsUserAllowed(user, ctx.RemoteAddr().String()) {
			a.logger.Warnf("User %s not authorized for access", user)
			return false
		}

		// Check root login permissions
		if !a.authorizer.IsRootLoginAllowed(user, "password") {
			a.logger.Warnf("Root password login denied for user %s", user)
			return false
		}

		// Use msteinert/pam for system authentication
		success := a.authenticateWithPAM(user, password)

		if success {
			a.logger.Infof("Password authentication successful for user %s", user)
		} else {
			a.logger.Warnf("Password authentication failed for user %s", user)
		}

		return success
	}
}

// CreatePublicKeyHandler creates an SSH public key authentication handler.
// Uses golang.org/x/crypto/ssh for authorized_keys parsing and validation.
// Also supports SSH certificate authentication when TrustedUserCAKeys is configured.
func (a *AuthHandler) CreatePublicKeyHandler() ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		user := ctx.User()

		// Check if public key authentication is enabled
		if !a.config.PubkeyAuthentication {
			a.logger.Debugf("Public key authentication disabled, rejecting user %s", user)
			return false
		}

		a.logger.Infof("Public key authentication attempt for user %s from %s", user, ctx.RemoteAddr())

		// Check user authorization first (before expensive key operations)
		if !a.authorizer.IsUserAllowed(user, ctx.RemoteAddr().String()) {
			a.logger.Warnf("User %s not authorized for access", user)
			return false
		}

		// Check root login permissions
		if !a.authorizer.IsRootLoginAllowed(user, "publickey") {
			a.logger.Warnf("Root public key login denied for user %s", user)
			return false
		}

		// Check if this is a certificate - certificates implement PublicKey interface
		if cert, ok := key.(*gossh.Certificate); ok {
			// Try certificate authentication first
			if a.certValidator != nil && a.certValidator.IsCertificateAuthenticationEnabled() {
				a.logger.Debugf("Certificate detected for user %s, attempting certificate validation", user)
				if err := a.certValidator.ValidateCertificate(user, cert); err == nil {
					a.logger.Infof("Certificate authentication successful for user %s", user)
					return true
				}
				a.logger.Debugf("Certificate validation failed for user %s, falling back to authorized_keys", user)
			} else {
				a.logger.Debugf("Certificate authentication not configured, treating as regular public key")
			}
		}

		// Use crypto/ssh for authorized keys validation (standard public keys and fallback for certs)
		success := a.validatePublicKey(ctx, user, key, ctx.RemoteAddr().String())

		if success {
			a.logger.Infof("Public key authentication successful for user %s", user)
		} else {
			a.logger.Warnf("Public key authentication failed for user %s", user)
		}

		return success
	}
}

// CreateKeyboardInteractiveHandler creates an SSH keyboard-interactive authentication handler.
// Uses msteinert/pam for challenge-response authentication with OpenSSH compatibility.
// This method allows for multi-factor authentication, one-time passwords, and custom prompts.
func (a *AuthHandler) CreateKeyboardInteractiveHandler() ssh.KeyboardInteractiveHandler {
	return func(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
		user := ctx.User()

		// Check if keyboard-interactive authentication is enabled
		if !a.config.KbdInteractiveAuthentication {
			a.logger.Debugf("Keyboard-interactive authentication disabled, rejecting user %s", user)
			return false
		}

		a.logger.Infof("Keyboard-interactive authentication attempt for user %s from %s", user, ctx.RemoteAddr())

		// Check user authorization first (before expensive auth operations)
		if !a.authorizer.IsUserAllowed(user, ctx.RemoteAddr().String()) {
			a.logger.Warnf("User %s not authorized for access", user)
			return false
		}

		// Check root login permissions
		if !a.authorizer.IsRootLoginAllowed(user, "keyboard-interactive") {
			a.logger.Warnf("Root keyboard-interactive login denied for user %s", user)
			return false
		}

		// Use PAM for keyboard-interactive authentication
		success := a.authenticateKeyboardInteractive(user, challenger)

		if success {
			a.logger.Infof("Keyboard-interactive authentication successful for user %s", user)
		} else {
			a.logger.Warnf("Keyboard-interactive authentication failed for user %s", user)
		}

		return success
	}
}

// authenticateWithPAM performs password authentication using PAM.
// This delegates all authentication logic to the msteinert/pam library.
func (a *AuthHandler) authenticateWithPAM(username, password string) bool {
	// Use PAM service name "sshd" for compatibility with OpenSSH
	tx, err := pam.StartFunc("sshd", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			// Return the password for password prompts
			return password, nil
		case pam.PromptEchoOn:
			// Return empty for username prompts (already provided)
			return "", nil
		case pam.ErrorMsg, pam.TextInfo:
			// Log PAM messages
			a.logger.Debugf("PAM message for %s: %s", username, msg)
			return "", nil
		default:
			return "", fmt.Errorf("unsupported PAM conversation style: %v", s)
		}
	})
	if err != nil {
		a.logger.Errorf("Failed to start PAM transaction for user %s: %v", username, err)
		return false
	}

	// Perform PAM authentication
	if err := tx.Authenticate(0); err != nil {
		a.logger.Debugf("PAM authentication failed for user %s: %v", username, err)
		return false
	}

	// Check account validity
	if err := tx.AcctMgmt(0); err != nil {
		a.logger.Debugf("PAM account check failed for user %s: %v", username, err)
		return false
	}

	return true
}

// validatePublicKey validates a public key against authorized_keys files.
// Uses golang.org/x/crypto/ssh for all key parsing and comparison.
func (a *AuthHandler) validatePublicKey(ctx ssh.Context, username string, clientKey ssh.PublicKey, remoteAddr string) bool {
	// Get user information to find home directory
	userInfo, err := user.Lookup(username)
	if err != nil {
		a.logger.Debugf("User lookup failed for %s: %v", username, err)
		return false
	}

	// Check all configured authorized keys files
	for _, keyFile := range a.config.AuthorizedKeysFile {
		if a.checkAuthorizedKeysFile(ctx, userInfo, keyFile, clientKey, remoteAddr) {
			return true
		}
	}

	return false
}

// checkAuthorizedKeysFile checks a single authorized_keys file for the given public key.
// Uses crypto/ssh for all key parsing and comparison logic.
// Also parses and validates key options like command restrictions.
func (a *AuthHandler) checkAuthorizedKeysFile(ctx ssh.Context, userInfo *user.User, keyFile string, clientKey ssh.PublicKey, remoteAddr string) bool {
	// Handle relative paths and ~ expansion like OpenSSH
	var filePath string
	if strings.HasPrefix(keyFile, "~/") || !filepath.IsAbs(keyFile) {
		// Relative to user's home directory
		filePath = filepath.Join(userInfo.HomeDir, strings.TrimPrefix(keyFile, "~/"))
	} else {
		filePath = keyFile
	}

	// Open authorized_keys file
	file, err := os.Open(filePath)
	if err != nil {
		a.logger.Debugf("Cannot open authorized_keys file %s for user %s: %v", filePath, userInfo.Username, err)
		return false
	}
	defer file.Close()

	// Parse each line using crypto/ssh
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse authorized_keys options and extract the key part
		keyPart, options, err := ParseAuthorizedKeyOptions(line)
		if err != nil {
			a.logger.Debugf("Failed to parse authorized_keys line at %s:%d: %v", filePath, lineNum, err)
			continue
		}

		// Parse the public key using crypto/ssh
		authorizedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(keyPart))
		if err != nil {
			a.logger.Debugf("Failed to parse authorized key at %s:%d: %v", filePath, lineNum, err)
			continue
		}

		// Compare keys by comparing their wire format (most reliable method)
		if string(authorizedKey.Marshal()) == string(clientKey.Marshal()) {
			a.logger.Debugf("Matching public key found in %s:%d for user %s", filePath, lineNum, userInfo.Username)

			// Validate key options if present
			if options != nil && !a.validateKeyOptions(ctx, options, userInfo.Username, remoteAddr) {
				a.logger.Warnf("Public key found but options validation failed for user %s", userInfo.Username)
				return false
			}

			return true
		}
	}

	if err := scanner.Err(); err != nil {
		a.logger.Errorf("Error reading authorized_keys file %s: %v", filePath, err)
	}

	return false
}

// validateKeyOptions validates authorized_keys options and applies restrictions.
// Stores validated options in the session context for enforcement by session handlers.
// Returns false if the key should be rejected due to option restrictions.
func (a *AuthHandler) validateKeyOptions(ctx ssh.Context, options *AuthorizedKeyOptions, username, remoteAddr string) bool {
	// Store options in context for session handlers to enforce
	ctx.SetValue(ContextKeyAuthorizedKeyOptions, options)

	if options.Command != "" {
		a.logger.Infof("Key has command restriction for user %s: %s", username, options.Command)
	}

	if len(options.From) > 0 {
		a.logger.Debugf("Key has source address restrictions for user %s: %v", username, options.From)

		// Validate source address against allowed patterns
		if !a.validateSourceAddress(remoteAddr, options.From, username) {
			a.logger.Warnf("Source address %s not allowed for user %s", remoteAddr, username)
			return false
		}
	}

	if options.NoPortForwarding {
		a.logger.Debugf("Key disables port forwarding for user %s", username)
	}

	if options.NoPTY {
		a.logger.Debugf("Key disables PTY for user %s", username)
	}

	// Options are now stored in context and will be enforced by session handlers
	return true
}

// validateSourceAddress validates if the remote address matches any of the allowed patterns.
// This implements OpenSSH-compatible "from" option validation for authorized keys.
// Supports IP addresses, CIDR blocks, and hostname patterns with wildcards.
func (a *AuthHandler) validateSourceAddress(remoteAddr string, allowedPatterns []string, username string) bool {
	// Extract IP address from remote address (format: "ip:port")
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If splitting fails, use the entire string (might be just an IP)
		host = remoteAddr
	}

	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		a.logger.Warnf("Could not parse remote IP address: %s", host)
		return false
	}

	for _, pattern := range allowedPatterns {
		pattern = strings.TrimSpace(pattern)

		// Check for CIDR notation
		if strings.Contains(pattern, "/") {
			_, network, err := net.ParseCIDR(pattern)
			if err != nil {
				a.logger.Debugf("Invalid CIDR pattern '%s' for user %s: %v", pattern, username, err)
				continue
			}
			if network.Contains(remoteIP) {
				a.logger.Debugf("Remote address %s matches CIDR pattern %s for user %s", host, pattern, username)
				return true
			}
		} else if ip := net.ParseIP(pattern); ip != nil {
			// Direct IP address match
			if ip.Equal(remoteIP) {
				a.logger.Debugf("Remote address %s matches IP pattern %s for user %s", host, pattern, username)
				return true
			}
		} else {
			// Hostname pattern matching (basic implementation)
			// For production, this should do proper reverse DNS lookup and pattern matching
			a.logger.Debugf("Hostname pattern matching not fully implemented for pattern '%s'", pattern)
			// As a fallback, do simple string comparison
			if host == pattern {
				a.logger.Debugf("Remote address %s matches hostname pattern %s for user %s", host, pattern, username)
				return true
			}
		}
	}

	return false
}

// authenticateKeyboardInteractive performs keyboard-interactive authentication using PAM.
// This is a thin wrapper that connects PAM's conversation interface with SSH's challenger.
// Library-first approach: all authentication logic delegated to msteinert/pam library.
func (a *AuthHandler) authenticateKeyboardInteractive(username string, challenger gossh.KeyboardInteractiveChallenge) bool {
	// Use PAM service name "sshd" for compatibility with OpenSSH
	tx, err := pam.StartFunc("sshd", username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			// Password prompt - request with echo disabled
			answers, err := challenger("", "", []string{msg}, []bool{false})
			if err != nil {
				a.logger.Debugf("Challenger failed for user %s: %v", username, err)
				return "", err
			}
			if len(answers) == 0 {
				return "", fmt.Errorf("no answer provided")
			}
			return answers[0], nil

		case pam.PromptEchoOn:
			// Username or visible prompt - request with echo enabled
			answers, err := challenger("", "", []string{msg}, []bool{true})
			if err != nil {
				a.logger.Debugf("Challenger failed for user %s: %v", username, err)
				return "", err
			}
			if len(answers) == 0 {
				return "", fmt.Errorf("no answer provided")
			}
			return answers[0], nil

		case pam.ErrorMsg:
			// Error message - send to client as instruction
			_, err := challenger("", msg, []string{}, []bool{})
			if err != nil {
				a.logger.Debugf("Failed to send error message to client for user %s: %v", username, err)
			}
			return "", nil

		case pam.TextInfo:
			// Informational message - send to client as instruction
			_, err := challenger("", msg, []string{}, []bool{})
			if err != nil {
				a.logger.Debugf("Failed to send info message to client for user %s: %v", username, err)
			}
			return "", nil

		default:
			return "", fmt.Errorf("unsupported PAM conversation style: %v", s)
		}
	})
	if err != nil {
		a.logger.Errorf("Failed to start PAM transaction for user %s: %v", username, err)
		return false
	}

	// Perform PAM authentication
	if err := tx.Authenticate(0); err != nil {
		a.logger.Debugf("PAM keyboard-interactive authentication failed for user %s: %v", username, err)
		return false
	}

	// Check account validity
	if err := tx.AcctMgmt(0); err != nil {
		a.logger.Debugf("PAM account check failed for user %s: %v", username, err)
		return false
	}

	return true
}
