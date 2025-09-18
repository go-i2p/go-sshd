// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
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
// This integrates pkg/sftp.Server with SSH session management.
func (h *SFTPHandler) CreateSubsystemHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		user := s.User()
		h.logger.Infof("SFTP subsystem started for user %s from %s", user, s.RemoteAddr())

		// Create SFTP server using pkg/sftp - handles all protocol details
		server, err := sftp.NewServer(s, h.buildServerOptions()...)
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

// buildServerOptions creates SFTP server options based on configuration.
// Uses pkg/sftp configuration options for server behavior.
func (h *SFTPHandler) buildServerOptions() []sftp.ServerOption {
	var options []sftp.ServerOption

	// Add debug logging if needed
	if h.logger.Level == logrus.DebugLevel {
		options = append(options, sftp.WithDebug(h.logger.Writer()))
	}

	// Configure working directory (defaults to user's home or root)
	// This can be enhanced later with proper user home directory resolution
	options = append(options, sftp.WithServerWorkingDirectory("/"))

	return options
}

// GetSupportedSubsystems returns the list of supported subsystems.
// Currently only supports "sftp" via pkg/sftp integration.
func (h *SFTPHandler) GetSupportedSubsystems() []string {
	return []string{"sftp"}
}

// ConfigureChroot configures SFTP chroot functionality if enabled.
// This is a placeholder for future chroot implementation.
func (h *SFTPHandler) ConfigureChroot(user string) (string, error) {
	// TODO: Implement chroot configuration based on sshd_config
	// For now, allow access to entire filesystem (like default OpenSSH)
	h.logger.Debugf("SFTP chroot not configured for user %s, using filesystem root", user)
	return "/", nil
}

// ValidateFileOperation validates file operations based on configuration.
// This is a placeholder for future access control implementation.
func (h *SFTPHandler) ValidateFileOperation(user, path, operation string) error {
	// TODO: Implement file operation validation based on configuration
	// For now, allow all operations (like default OpenSSH SFTP)
	h.logger.Debugf("SFTP operation %s on %s allowed for user %s", operation, path, user)
	return nil
}
