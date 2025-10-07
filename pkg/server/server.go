// Package server provides the core SSH server implementation.
// This package wraps gliderlabs/ssh to create an OpenSSH-compatible server.
package server

import (
	"fmt"
	"net"

	"github.com/gliderlabs/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/crypto"
	"github.com/go-i2p/go-sshd/pkg/handlers"
	"github.com/go-i2p/go-sshd/pkg/logging"
	"github.com/go-i2p/go-sshd/pkg/signals"
)

// Server wraps gliderlabs/ssh with OpenSSH-compatible configuration.
// This is a thin wrapper that coordinates library functionality.
type Server struct {
	config        *config.Config
	configFile    string // Store config file path for reload
	ssh           *ssh.Server
	logger        *logging.Logger
	signalHandler *signals.Handler
}

// New creates a new SSH server with the given configuration.
// This function integrates gliderlabs/ssh with our configuration system.
func New(cfg *config.Config) (*Server, error) {
	return NewWithConfigFile(cfg, "")
}

// NewWithConfigFile creates a new SSH server with configuration and config file path.
// The config file path is used for configuration reload on SIGHUP.
func NewWithConfigFile(cfg *config.Config, configFile string) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	// Create centralized logger from configuration
	logger, err := logging.NewLogger(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create signal handler for graceful shutdown and config reload
	signalHandler := signals.NewHandler()

	server := &Server{
		config:        cfg,
		configFile:    configFile,
		logger:        logger,
		signalHandler: signalHandler,
	}

	// Initialize SSH server with current configuration
	if err := server.initializeSSHServer(); err != nil {
		signalHandler.Stop()
		return nil, err
	}

	return server, nil
}

// initializeSSHServer sets up the gliderlabs/ssh server with current configuration.
// This method can be called during initialization and configuration reload.
func (s *Server) initializeSSHServer() error {
	// Create gliderlabs/ssh server with basic options
	sshServer := &ssh.Server{
		Addr: fmt.Sprintf(":%d", s.config.Port),
	}

	// Configure host keys using the new HostKeyManager
	hostKeyManager := crypto.NewHostKeyManager(s.config.HostKey)
	signers, err := hostKeyManager.LoadOrGenerateKeys()
	if err != nil {
		return fmt.Errorf("failed to load or generate host keys: %w", err)
	}

	// Add all signers to the SSH server
	for i, signer := range signers {
		if err := crypto.ValidateHostKey(signer); err != nil {
			s.logger.Errorf("Invalid host key %d: %v", i, err)
			continue
		}

		sshServer.AddHostKey(signer)
		fingerprint := crypto.GetKeyFingerprint(signer.PublicKey())
		keyType := crypto.GetKeyType(signer.PublicKey())
		s.logger.Infof("Loaded host key: %s %s", keyType, fingerprint)
	}

	if len(signers) == 0 {
		return fmt.Errorf("no valid host keys loaded")
	}

	// Configure authentication handlers using the new AuthHandler
	if s.config.PasswordAuthentication || s.config.PubkeyAuthentication {
		authHandler := handlers.NewAuthHandler(s.config, s.logger.GetLogrus())
		sshServer.PasswordHandler = authHandler.CreatePasswordHandler()
		sshServer.PublicKeyHandler = authHandler.CreatePublicKeyHandler()
	}

	// Configure session handler using the new ShellHandler
	shellHandler := handlers.NewShellHandler(s.logger.GetLogrus())
	sshServer.Handler = shellHandler.CreateSessionHandler()

	// Configure SFTP subsystem handler
	sftpHandler := handlers.NewSFTPHandler(s.config, s.logger.GetLogrus())
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": sftpHandler.CreateSubsystemHandler(),
	}

	// Configure port forwarding handlers if TCP forwarding is enabled
	if s.config.AllowTcpForwarding {
		forwardingHandler := handlers.NewForwardingHandler(s.config, s.logger.GetLogrus())

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

		s.logger.Info("Port forwarding enabled: local, remote, and direct TCP/IP forwarding")
	} else {
		s.logger.Info("Port forwarding disabled by configuration")
	}

	s.ssh = sshServer
	return nil
}

// Start starts the SSH server in foreground mode.
// This method blocks until the server is stopped by signal or context cancellation.
func (s *Server) Start() error {
	s.logger.Infof("Starting SSH server on port %d", s.config.Port)

	// Start signal handling in background
	go s.handleSignals()

	// Start the gliderlabs/ssh server with context support
	s.logger.Info("SSH server started successfully")

	// Use context to control server lifecycle
	ctx := s.signalHandler.Context()

	// Start server in a goroutine so we can handle context cancellation
	serverErr := make(chan error, 1)
	go func() {
		err := s.ssh.ListenAndServe()
		if err != nil && err != ssh.ErrServerClosed {
			serverErr <- fmt.Errorf("server error: %w", err)
		} else {
			serverErr <- nil
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Received shutdown signal, stopping server...")
		// Gracefully close the server
		if err := s.ssh.Close(); err != nil {
			s.logger.Errorf("Error closing server: %v", err)
		}
		// Wait for server to actually stop
		<-serverErr
	case err := <-serverErr:
		if err != nil {
			return err
		}
	}

	s.logger.Info("SSH server stopped")
	return nil
}

// handleSignals runs in a background goroutine to handle configuration reload signals.
// This method handles SIGHUP for configuration reload while keeping the server running.
func (s *Server) handleSignals() {
	for {
		sig := s.signalHandler.WaitForReload()
		if sig == nil {
			// Context cancelled, server shutting down
			return
		}

		s.logger.Infof("Received %s signal, reloading configuration...", sig)
		if err := s.reloadConfiguration(); err != nil {
			s.logger.Errorf("Failed to reload configuration: %v", err)
		} else {
			s.logger.Info("Configuration reloaded successfully")
		}
	}
}

// reloadConfiguration reloads the server configuration from the config file.
// This method is called when SIGHUP is received, allowing dynamic configuration updates.
func (s *Server) reloadConfiguration() error {
	if s.configFile == "" {
		return fmt.Errorf("no config file specified for reload")
	}

	// Load new configuration
	newConfig, err := config.Load(s.configFile)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	// Update logger configuration first (this is safe to do while server is running)
	newLogger, err := logging.NewLogger(newConfig)
	if err != nil {
		return fmt.Errorf("failed to create new logger: %w", err)
	}

	// Store old config and logger for rollback if needed
	oldConfig := s.config
	oldLogger := s.logger

	// Update configuration and logger
	s.config = newConfig
	s.logger = newLogger

	s.logger.Info("Configuration reloaded - server restart required for some changes to take effect")
	s.logger.Info("To apply all configuration changes, restart the server")

	// Note: For full configuration reload (including port changes, host keys, etc),
	// a server restart is required. This implementation only reloads logger settings
	// which can be changed dynamically. Future enhancement could add more dynamic reload capabilities.

	_ = oldConfig // Keep for potential rollback logic
	_ = oldLogger // Keep for potential rollback logic

	return nil
}

// Stop gracefully stops the SSH server and cleans up resources.
// This method can be called programmatically to shutdown the server.
func (s *Server) Stop() error {
	s.logger.Info("Stopping SSH server...")

	// Trigger shutdown
	s.signalHandler.Shutdown()

	// Close the SSH server
	if s.ssh != nil {
		if err := s.ssh.Close(); err != nil {
			s.logger.Errorf("Error closing SSH server: %v", err)
		}
	}

	// Stop signal handler
	s.signalHandler.Stop()

	s.logger.Info("SSH server stopped")
	return nil
}

// StartDaemon starts the server in daemon mode (same as Start for now).
// Future implementation could add proper daemonization with fork/exec.
func (s *Server) StartDaemon() error {
	return s.Start()
}

// NewInetd creates a new SSH server configured for inetd/socket activation mode.
// This mode is used when the server is started by systemd socket activation.
func NewInetd(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	// Create centralized logger from configuration
	logger, err := logging.NewLogger(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	server := &Server{
		config: cfg,
		logger: logger,
		// No signal handler needed for inetd mode
	}

	// Initialize SSH server with current configuration
	if err := server.initializeSSHServer(); err != nil {
		return nil, err
	}

	return server, nil
}

// HandleConnection handles a single SSH connection in inetd mode.
// This method is used for systemd socket activation where each connection
// is handled by a separate process instance.
func (s *Server) HandleConnection(conn net.Conn) error {
	s.logger.Info("Handling SSH connection in inetd mode")

	// Handle the connection using gliderlabs/ssh
	// Note: HandleConn doesn't return an error, it blocks until connection closes
	s.ssh.HandleConn(conn)

	s.logger.Info("SSH connection completed")
	return nil
}
