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
	"github.com/go-i2p/go-sshd/pkg/metrics"
	"github.com/go-i2p/go-sshd/pkg/signals"
)

// Server wraps gliderlabs/ssh with OpenSSH-compatible configuration.
// This is a thin wrapper that coordinates library functionality.
type Server struct {
	config           *config.Config
	configFile       string // Store config file path for reload
	ssh              *ssh.Server
	logger           *logging.Logger
	signalHandler    *signals.Handler
	metricsCollector *metrics.Collector
	metricsServer    *metrics.Server
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

	// Initialize metrics if enabled
	if cfg.MetricsEnabled {
		server.metricsCollector = metrics.NewCollector(logger.GetLogrus())
		server.metricsServer = metrics.NewServer(server.metricsCollector, cfg.MetricsAddress, logger)
		logger.Infof("Metrics collection enabled, will listen on %s", cfg.MetricsAddress)
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

	// Configure all server components
	if err := s.configureHostKeys(sshServer); err != nil {
		return err
	}

	s.configureAuthentication(sshServer)
	s.configureSessionHandlers(sshServer)
	s.configurePortForwarding(sshServer)
	s.configureAgentForwarding(sshServer)
	s.configureX11Forwarding(sshServer)

	s.ssh = sshServer
	return nil
}

// configureHostKeys loads or generates host keys and adds them to the SSH server.
func (s *Server) configureHostKeys(sshServer *ssh.Server) error {
	hostKeyManager := crypto.NewHostKeyManager(s.config.HostKey)
	signers, err := hostKeyManager.LoadOrGenerateKeys()
	if err != nil {
		return fmt.Errorf("failed to load or generate host keys: %w", err)
	}

	validSigners := 0
	for i, signer := range signers {
		if err := crypto.ValidateHostKey(signer); err != nil {
			s.logger.Errorf("Invalid host key %d: %v", i, err)
			continue
		}

		sshServer.AddHostKey(signer)
		fingerprint := crypto.GetKeyFingerprint(signer.PublicKey())
		keyType := crypto.GetKeyType(signer.PublicKey())
		s.logger.Infof("Loaded host key: %s %s", keyType, fingerprint)
		validSigners++
	}

	if validSigners == 0 {
		return fmt.Errorf("no valid host keys loaded")
	}

	return nil
}

// configureAuthentication sets up password, public key, and keyboard-interactive authentication handlers.
func (s *Server) configureAuthentication(sshServer *ssh.Server) {
	if s.config.PasswordAuthentication || s.config.PubkeyAuthentication || s.config.KbdInteractiveAuthentication {
		authHandler := handlers.NewAuthHandler(s.config, s.logger.GetLogrus())
		sshServer.PasswordHandler = authHandler.CreatePasswordHandler()
		sshServer.PublicKeyHandler = authHandler.CreatePublicKeyHandler()
		sshServer.KeyboardInteractiveHandler = authHandler.CreateKeyboardInteractiveHandler()
	}
}

// configureSessionHandlers sets up shell session and SFTP subsystem handlers.
func (s *Server) configureSessionHandlers(sshServer *ssh.Server) {
	// Configure session handler
	shellHandler := handlers.NewShellHandler(s.logger.GetLogrus())
	sshServer.Handler = shellHandler.CreateSessionHandler()

	// Configure SFTP subsystem handler
	sftpHandler := handlers.NewSFTPHandler(s.config, s.logger.GetLogrus())
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": sftpHandler.CreateSubsystemHandler(),
	}
}

// configurePortForwarding sets up local, remote, and direct TCP/IP port forwarding handlers.
func (s *Server) configurePortForwarding(sshServer *ssh.Server) {
	if !s.config.AllowTcpForwarding {
		s.logger.Info("Port forwarding disabled by configuration")
		return
	}

	forwardingHandler := handlers.NewForwardingHandler(s.config, s.logger.GetLogrus())

	// Set port forwarding callbacks
	sshServer.LocalPortForwardingCallback = forwardingHandler.CreateLocalPortForwardHandler()
	sshServer.ReversePortForwardingCallback = forwardingHandler.CreateReversePortForwardHandler()

	// Initialize channel and request handlers if needed
	if sshServer.ChannelHandlers == nil {
		sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
	}
	if sshServer.RequestHandlers == nil {
		sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
	}

	// Add direct-tcpip channel handler
	sshServer.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler

	// Add request handlers for remote forwarding
	tcpHandler := forwardingHandler.GetTCPHandler()
	sshServer.RequestHandlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
	sshServer.RequestHandlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest

	s.logger.Info("Port forwarding enabled: local, remote, and direct TCP/IP forwarding")
}

// configureAgentForwarding sets up SSH agent forwarding handlers.
func (s *Server) configureAgentForwarding(sshServer *ssh.Server) {
	if !s.config.AllowAgentForwarding {
		s.logger.Info("SSH agent forwarding disabled by configuration")
		return
	}

	agentHandler := handlers.NewAgentHandler(s.config, s.logger.GetLogrus())

	// Initialize handlers if needed
	if sshServer.ChannelHandlers == nil {
		sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
	}
	if sshServer.RequestHandlers == nil {
		sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
	}

	// Add agent forwarding handlers
	sshServer.ChannelHandlers["auth-agent@openssh.com"] = agentHandler.CreateAgentForwardingHandler()
	sshServer.RequestHandlers["auth-agent-req@openssh.com"] = agentHandler.CreateAgentRequestHandler()

	s.logger.Info("SSH agent forwarding enabled")
}

// configureX11Forwarding sets up X11 display forwarding handlers.
func (s *Server) configureX11Forwarding(sshServer *ssh.Server) {
	if !s.config.X11Forwarding {
		s.logger.Info("X11 forwarding disabled by configuration")
		return
	}

	x11Handler := handlers.NewX11Handler(s.config, s.logger.GetLogrus())

	// Initialize handlers if needed
	if sshServer.ChannelHandlers == nil {
		sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
	}
	if sshServer.RequestHandlers == nil {
		sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
	}

	// Add X11 forwarding handlers
	sshServer.ChannelHandlers["x11"] = x11Handler.CreateX11ChannelHandler()
	sshServer.RequestHandlers["x11-req"] = x11Handler.CreateX11RequestHandler()

	s.logger.WithFields(map[string]interface{}{
		"displayOffset": s.config.X11DisplayOffset,
		"useLocalhost":  s.config.X11UseLocalhost,
	}).Info("X11 forwarding enabled")
}

// Start starts the SSH server in foreground mode.
// This method blocks until the server is stopped by signal or context cancellation.
func (s *Server) Start() error {
	s.logger.Infof("Starting SSH server on port %d", s.config.Port)

	// Start metrics server if enabled
	if s.metricsServer != nil {
		if err := s.metricsServer.Start(); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		s.logger.Info("Metrics server started")
	}

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
		// Stop metrics server if running
		if s.metricsServer != nil {
			if err := s.metricsServer.Stop(); err != nil {
				s.logger.Errorf("Error stopping metrics server: %v", err)
			}
		}
		// Wait for server to actually stop
		<-serverErr
	case err := <-serverErr:
		if err != nil {
			// Also stop metrics server on error
			if s.metricsServer != nil {
				s.metricsServer.Stop()
			}
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

	// Stop metrics server if running
	if s.metricsServer != nil {
		if err := s.metricsServer.Stop(); err != nil {
			s.logger.Errorf("Error stopping metrics server: %v", err)
		} else {
			s.logger.Info("Metrics server stopped")
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
