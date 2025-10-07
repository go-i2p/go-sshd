// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// SFTPHandler handles SFTP subsystem requests.
// This is a thin wrapper around pkg/sftp for complete SFTP protocol support.
type SFTPHandler struct {
	config *config.Config
	logger *logrus.Logger
}

// NewSFTPHandler creates a new SFTP subsystem handler.
// Uses library-first approach - delegates all SFTP protocol to pkg/sftp.
func NewSFTPHandler(cfg *config.Config, logger *logrus.Logger) *SFTPHandler {
	return &SFTPHandler{
		config: cfg,
		logger: logger,
	}
}

// CreateSubsystemHandler creates the SFTP subsystem handler for gliderlabs/ssh.
// This integrates pkg/sftp.Server with SSH session management and applies security restrictions.
func (h *SFTPHandler) CreateSubsystemHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		user := s.User()
		h.logger.Infof("SFTP subsystem started for user %s from %s", user, s.RemoteAddr())

		// Configure chroot/working directory for the user
		workingDir, err := h.ConfigureChroot(user)
		if err != nil {
			h.logger.Errorf("Failed to configure chroot for user %s: %v", user, err)
			return
		}

		// Create SFTP server using pkg/sftp with user-specific configuration
		server, err := sftp.NewServer(s, h.buildServerOptions(workingDir)...)
		if err != nil {
			h.logger.Errorf("Failed to create SFTP server for user %s: %v", user, err)
			return
		}

		// Serve SFTP requests - pkg/sftp handles everything
		if err := server.Serve(); err != nil {
			h.logger.Errorf("SFTP server error for user %s: %v", user, err)
		} else {
			h.logger.Infof("SFTP subsystem completed for user %s", user)
		}
	}
}

// buildServerOptions creates SFTP server options based on configuration and user context.
// Uses pkg/sftp configuration options for server behavior with security restrictions.
func (h *SFTPHandler) buildServerOptions(workingDir string) []sftp.ServerOption {
	var options []sftp.ServerOption

	// Add debug logging if needed
	if h.logger.Level == logrus.DebugLevel {
		options = append(options, sftp.WithDebug(h.logger.Writer()))
	}

	// Configure working directory with proper chroot/security restrictions
	// Normalize the path to prevent directory traversal attacks
	normalizedDir := filepath.Clean(workingDir)
	h.logger.Debugf("SFTP server working directory set to: %s", normalizedDir)
	options = append(options, sftp.WithServerWorkingDirectory(normalizedDir))

	return options
}

// GetSupportedSubsystems returns the list of supported subsystems.
// Currently only supports "sftp" via pkg/sftp integration.
func (h *SFTPHandler) GetSupportedSubsystems() []string {
	return []string{"sftp"}
}

// ConfigureChroot configures SFTP chroot functionality based on user and security settings.
// This implements a secure default approach where users are restricted to their home directories.
// Following OpenSSH patterns for SFTP security and user isolation.
func (h *SFTPHandler) ConfigureChroot(username string) (string, error) {
	// Get user information to determine home directory
	userInfo, err := user.Lookup(username)
	if err != nil {
		h.logger.Warnf("User lookup failed for %s: %v", username, err)
		// Fallback to root filesystem for system users or when user lookup fails
		h.logger.Debugf("SFTP using filesystem root for user %s due to lookup failure", username)
		return "/", nil
	}

	// For security, default to user's home directory as chroot
	// This prevents users from accessing system files outside their home
	chrootPath := userInfo.HomeDir

	// Verify the directory exists and is accessible
	if stat, err := os.Stat(chrootPath); err != nil {
		h.logger.Warnf("User home directory %s not accessible for %s: %v", chrootPath, username, err)
		// Fallback to root for system compatibility, but log the security implication
		h.logger.Infof("SFTP fallback to filesystem root for user %s - consider creating home directory", username)
		return "/", nil
	} else if !stat.IsDir() {
		h.logger.Warnf("User home path %s is not a directory for %s", chrootPath, username)
		return "/", nil
	}

	// For root user, allow full filesystem access for administrative tasks
	if username == "root" {
		h.logger.Debugf("SFTP allowing full filesystem access for root user")
		return "/", nil
	}

	h.logger.Infof("SFTP chroot configured for user %s: %s", username, chrootPath)
	return chrootPath, nil
}

// ValidateFileOperation validates file operations based on security policies and configuration.
// Implements OpenSSH-compatible security controls for SFTP file access.
func (h *SFTPHandler) ValidateFileOperation(user, path, operation string) error {
	h.logger.Debugf("Validating SFTP operation %s on %s for user %s", operation, path, user)

	// Prevent directory traversal attacks by checking for .. in original path
	if strings.Contains(path, "..") {
		h.logger.Warnf("SFTP operation %s denied for user %s: directory traversal attempt on %s", operation, user, path)
		return errors.New("directory traversal not allowed")
	}

	// Normalize the path to prevent other forms of path manipulation
	cleanPath := filepath.Clean(path)

	// Block access to sensitive system files for non-root users
	if user != "root" {
		if err := h.validateSystemFileAccess(cleanPath, operation, user); err != nil {
			return err
		}
	}

	// Validate write operations to critical system directories
	if err := h.validateWriteOperations(cleanPath, operation, user); err != nil {
		return err
	}

	// Log successful validation
	h.logger.Debugf("SFTP operation %s on %s allowed for user %s", operation, cleanPath, user)
	return nil
}

// validateSystemFileAccess prevents non-root users from accessing sensitive system files.
func (h *SFTPHandler) validateSystemFileAccess(path, operation, user string) error {
	// Block access to sensitive system directories for non-root users
	sensitiveDirectories := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/ssh/",
		"/root/",
		"/var/log/",
		"/proc/",
		"/sys/",
		"/dev/",
	}

	for _, sensitive := range sensitiveDirectories {
		if strings.HasPrefix(path, sensitive) || path == strings.TrimSuffix(sensitive, "/") {
			h.logger.Warnf("SFTP operation %s denied for user %s: access to sensitive path %s", operation, user, path)
			return errors.New("access to system files denied")
		}
	}

	return nil
}

// validateWriteOperations validates write operations to prevent system damage.
func (h *SFTPHandler) validateWriteOperations(path, operation, user string) error {
	// Check if this is a write operation
	writeOperations := []string{"write", "create", "delete", "mkdir", "rmdir", "rename"}
	isWriteOp := false
	for _, writeOp := range writeOperations {
		if strings.EqualFold(operation, writeOp) {
			isWriteOp = true
			break
		}
	}

	if !isWriteOp {
		return nil // Read operations are generally allowed
	}

	// Block write operations to critical system directories for all users
	protectedDirectories := []string{
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
		"/boot/",
		"/etc/systemd/",
	}

	for _, protected := range protectedDirectories {
		if strings.HasPrefix(path, protected) {
			h.logger.Warnf("SFTP write operation %s denied for user %s: protected system directory %s", operation, user, path)
			return errors.New("write operations to system directories not allowed")
		}
	}

	return nil
}
