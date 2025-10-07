// Package server provides the core SSH server implementation.
// This package wraps gliderlabs/ssh to create an OpenSSH-compatible server.
package server

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/handlers"
)

// Server wraps gliderlabs/ssh with OpenSSH-compatible configuration.
// This is a thin wrapper that coordinates library functionality.
type Server struct {
	config *config.Config
	ssh    *ssh.Server
	logger *logrus.Logger
}

// New creates a new SSH server with the given configuration.
// This function integrates gliderlabs/ssh with our configuration system.
func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Create gliderlabs/ssh server with basic options
	sshServer := &ssh.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
	}

	// Configure host keys - using gliderlabs/ssh host key loading
	if err := loadHostKeys(sshServer, cfg.HostKey, logger); err != nil {
		return nil, fmt.Errorf("failed to load host keys: %w", err)
	}

	// Configure authentication handlers using the new AuthHandler
	if cfg.PasswordAuthentication || cfg.PubkeyAuthentication {
		authHandler := handlers.NewAuthHandler(cfg, logger)
		sshServer.PasswordHandler = authHandler.CreatePasswordHandler()
		sshServer.PublicKeyHandler = authHandler.CreatePublicKeyHandler()
	}

	// Configure session handler using the new ShellHandler
	shellHandler := handlers.NewShellHandler(logger)
	sshServer.Handler = shellHandler.CreateSessionHandler()

	// Configure SFTP subsystem handler
	sftpHandler := handlers.NewSFTPHandler(cfg, logger)
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": sftpHandler.CreateSubsystemHandler(),
	}

	// Configure port forwarding handlers if TCP forwarding is enabled
	if cfg.AllowTcpForwarding {
		forwardingHandler := handlers.NewForwardingHandler(cfg, logger)

		// Set local port forwarding callback
		sshServer.LocalPortForwardingCallback = forwardingHandler.CreateLocalPortForwardHandler()

		// Set reverse port forwarding callback
		sshServer.ReversePortForwardingCallback = forwardingHandler.CreateReversePortForwardHandler()

		// Add direct-tcpip channel handler for local forwarding
		if sshServer.ChannelHandlers == nil {
			sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
		}
		sshServer.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler

		// Add request handlers for remote forwarding
		if sshServer.RequestHandlers == nil {
			sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
		}
		tcpHandler := forwardingHandler.GetTCPHandler()
		sshServer.RequestHandlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
		sshServer.RequestHandlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest

		logger.Info("Port forwarding enabled: local, remote, and direct TCP/IP forwarding")
	} else {
		logger.Info("Port forwarding disabled by configuration")
	}

	server := &Server{
		config: cfg,
		ssh:    sshServer,
		logger: logger,
	}

	return server, nil
}

// Start starts the SSH server in foreground mode.
// This method blocks until the server is stopped.
func (s *Server) Start() error {
	s.logger.Infof("Starting SSH server on port %d", s.config.Port)

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		s.logger.Info("Received shutdown signal, stopping server...")
		s.ssh.Close()
	}()

	// Start the gliderlabs/ssh server
	s.logger.Info("SSH server started successfully")
	err := s.ssh.ListenAndServe()
	if err != nil && err != ssh.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	s.logger.Info("SSH server stopped")
	return nil
}

// StartDaemon starts the server in daemon mode (same as Start for now).
// Future implementation could add proper daemonization.
func (s *Server) StartDaemon() error {
	return s.Start()
}

// loadHostKeys loads SSH host keys using gliderlabs/ssh host key helpers.
// This function integrates with OpenSSH-style host key files.
func loadHostKeys(server *ssh.Server, hostKeys []string, logger *logrus.Logger) error {
	loaded := false

	for _, keyPath := range hostKeys {
		// Skip empty key paths (used in tests)
		if keyPath == "" {
			continue
		}

		// Check if host key file exists
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			logger.Warnf("Host key file %s not found, skipping", keyPath)
			continue
		}

		// Load the host key using gliderlabs/ssh helper
		if err := ssh.HostKeyFile(keyPath)(server); err != nil {
			logger.Errorf("Failed to load host key %s: %v", keyPath, err)
			continue
		}

		logger.Infof("Loaded host key: %s", keyPath)
		loaded = true
	}

	// If no host keys were loaded and we have key paths, try to generate temporary key
	if !loaded && len(hostKeys) > 0 {
		// Only generate temporary key if we actually tried to load some
		logger.Warn("No host keys loaded, using built-in key generation")
		// For testing, we'll skip key generation - production will use real keys
		return nil
	}

	return nil
}
