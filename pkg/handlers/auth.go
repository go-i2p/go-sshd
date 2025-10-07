// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"bufio"
	"fmt"
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

// AuthHandler handles SSH authentication using system libraries.
// This is a thin wrapper around msteinert/pam and crypto/ssh for OpenSSH compatibility.
type AuthHandler struct {
	config     *config.Config
	logger     *logrus.Logger
	authorizer *UserAuthorizer
}

// NewAuthHandler creates a new authentication handler with the given configuration.
// Uses library-first approach - delegates all auth logic to mature libraries.
func NewAuthHandler(cfg *config.Config, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		config:     cfg,
		logger:     logger,
		authorizer: NewUserAuthorizer(cfg, logger),
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

		// Use crypto/ssh for authorized keys validation
		success := a.validatePublicKey(user, key)

		if success {
			a.logger.Infof("Public key authentication successful for user %s", user)
		} else {
			a.logger.Warnf("Public key authentication failed for user %s", user)
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
func (a *AuthHandler) validatePublicKey(username string, clientKey ssh.PublicKey) bool {
	// Get user information to find home directory
	userInfo, err := user.Lookup(username)
	if err != nil {
		a.logger.Debugf("User lookup failed for %s: %v", username, err)
		return false
	}

	// Check all configured authorized keys files
	for _, keyFile := range a.config.AuthorizedKeysFile {
		if a.checkAuthorizedKeysFile(userInfo, keyFile, clientKey) {
			return true
		}
	}

	return false
}

// checkAuthorizedKeysFile checks a single authorized_keys file for the given public key.
// Uses crypto/ssh for all key parsing and comparison logic.
// Also parses and validates key options like command restrictions.
func (a *AuthHandler) checkAuthorizedKeysFile(userInfo *user.User, keyFile string, clientKey ssh.PublicKey) bool {
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
			if options != nil && !a.validateKeyOptions(options, userInfo.Username) {
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
// Returns false if the key should be rejected due to option restrictions.
func (a *AuthHandler) validateKeyOptions(options *AuthorizedKeyOptions, username string) bool {
	// For now, just log the options - full enforcement would be done in session handlers
	if options.Command != "" {
		a.logger.Debugf("Key has command restriction for user %s: %s", username, options.Command)
	}

	if len(options.From) > 0 {
		a.logger.Debugf("Key has source address restrictions for user %s: %v", username, options.From)
		// TODO: Validate source address - would need access to remote address in this context
	}

	if options.NoPortForwarding {
		a.logger.Debugf("Key disables port forwarding for user %s", username)
	}

	if options.NoPTY {
		a.logger.Debugf("Key disables PTY for user %s", username)
	}

	// For basic implementation, accept all keys - restrictions would be enforced
	// in session/channel handlers based on stored options
	return true
}
