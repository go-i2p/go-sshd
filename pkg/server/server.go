// Package server provides the core SSH server implementation.
// This package wraps gliderlabs/ssh to create an OpenSSH-compatible server.
package server

import (
	"fmt"
	"net"
	"sync"

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
	mu               sync.Mutex // protects config, logger, ssh, and sshErrCh below against concurrent SIGHUP reload
	config           *config.Config
	configFile       string // Store config file path for reload
	ssh              *ssh.Server
	sshErrCh         chan error // error channel for the currently-active ssh.Server; non-nil only while Start is running
	logger           *logging.Logger
	signalHandler    *signals.Handler
	metricsCollector *metrics.Collector
	metricsServer    *metrics.Server
}

// getLogger returns the current logger. Safe for concurrent use with reloadConfiguration,
// which replaces the logger when the configuration is reloaded via SIGHUP.
func (s *Server) getLogger() *logging.Logger {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logger
}

// getSSH returns the current gliderlabs/ssh server instance. Safe for concurrent
// use with reloadConfiguration, which replaces the server when the configuration
// is reloaded via SIGHUP.
func (s *Server) getSSH() *ssh.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ssh
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
	if err := s.startMetricsServer(); err != nil {
		return err
	}

	// Start signal handling in background
	go s.handleSignals()

	s.mu.Lock()
	s.sshErrCh = make(chan error, 1)
	errCh := s.sshErrCh
	sshServer := s.ssh
	s.mu.Unlock()

	go s.runSSHServer(sshServer, errCh)

	// Start the gliderlabs/ssh server with context support
	s.getLogger().Info("SSH server started successfully")

	// Wait for shutdown or error
	return s.runServerLoop()
}

// startMetricsServer starts the metrics server if configured.
func (s *Server) startMetricsServer() error {
	if s.metricsServer == nil {
		return nil
	}

	if err := s.metricsServer.Start(); err != nil {
		return fmt.Errorf("failed to start metrics server: %w", err)
	}
	s.getLogger().Info("Metrics server started")
	return nil
}

// runServerLoop waits for a shutdown signal or an SSH server error.
// A SIGHUP-triggered configuration reload closes the current SSH server and
// starts a new one against a new error channel; errors reported by a
// now-superseded generation are not treated as a fatal server error.
func (s *Server) runServerLoop() error {
	ctx := s.signalHandler.Context()

	for {
		s.mu.Lock()
		errCh := s.sshErrCh
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return s.handleShutdown(errCh)
		case err := <-errCh:
			s.mu.Lock()
			current := s.sshErrCh
			s.mu.Unlock()
			if current != errCh {
				// This error came from a server generation that was already
				// replaced by a configuration reload - keep running with the
				// current generation instead of treating this as a stop.
				continue
			}
			if err != nil {
				s.stopMetricsServer()
				return err
			}
			s.getLogger().Info("SSH server stopped")
			return nil
		}
	}
}

// runSSHServer starts the given SSH listener and reports its outcome on errCh.
func (s *Server) runSSHServer(sshServer *ssh.Server, errCh chan<- error) {
	err := sshServer.ListenAndServe()
	if err != nil && err != ssh.ErrServerClosed {
		errCh <- fmt.Errorf("server error: %w", err)
	} else {
		errCh <- nil
	}
}

// handleShutdown gracefully stops the server and metrics server.
func (s *Server) handleShutdown(errCh <-chan error) error {
	s.getLogger().Info("Received shutdown signal, stopping server...")

	// Gracefully close the server
	if err := s.getSSH().Close(); err != nil {
		s.getLogger().Errorf("Error closing server: %v", err)
	}

	// Stop metrics server if running
	s.stopMetricsServer()

	// Wait for server to actually stop
	<-errCh

	s.getLogger().Info("SSH server stopped")
	return nil
}

// stopMetricsServer stops the metrics server if running.
func (s *Server) stopMetricsServer() {
	if s.metricsServer != nil {
		if err := s.metricsServer.Stop(); err != nil {
			s.getLogger().Errorf("Error stopping metrics server: %v", err)
		}
	}
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

		s.getLogger().Infof("Received %s signal, reloading configuration...", sig)
		if err := s.reloadConfiguration(); err != nil {
			s.getLogger().Errorf("Failed to reload configuration: %v", err)
		} else {
			s.getLogger().Info("Configuration reloaded successfully")
		}
	}
}

// reloadConfiguration reloads the server configuration from the config file and
// rebuilds the SSH server (host keys, authentication, session, forwarding,
// agent, and X11 handlers) from it, matching initializeSSHServer. If the
// server is currently running, the previous SSH listener is closed and a new
// one is started against the rebuilt server so that subsequent connections
// are evaluated against the newly loaded configuration; connections already
// in flight continue to run under the handlers that were active when they
// were accepted.
func (s *Server) reloadConfiguration() error {
	if s.configFile == "" {
		return fmt.Errorf("no config file specified for reload")
	}

	// Load new configuration
	newConfig, err := config.Load(s.configFile)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	// Create a new logger from the new configuration
	newLogger, err := logging.NewLogger(newConfig)
	if err != nil {
		return fmt.Errorf("failed to create new logger: %w", err)
	}

	// Rebuild the SSH server (host keys, auth, session, forwarding, agent,
	// X11 handlers) against the new configuration/logger, using a throwaway
	// Server value so initializeSSHServer's existing logic can be reused
	// without touching the live server until the rebuild has succeeded.
	builder := &Server{config: newConfig, logger: newLogger}
	if err := builder.initializeSSHServer(); err != nil {
		return fmt.Errorf("failed to rebuild SSH server with new configuration: %w", err)
	}

	s.mu.Lock()
	oldSSHServer := s.ssh
	wasRunning := s.sshErrCh != nil
	s.config = newConfig
	s.logger = newLogger
	s.ssh = builder.ssh
	var newErrCh chan error
	if wasRunning {
		newErrCh = make(chan error, 1)
		s.sshErrCh = newErrCh
	}
	s.mu.Unlock()

	newLogger.Info("Configuration reloaded - new connections will use the updated configuration")

	if wasRunning {
		go s.runSSHServer(builder.ssh, newErrCh)
		if oldSSHServer != nil {
			if err := oldSSHServer.Close(); err != nil {
				newLogger.Warnf("Error closing previous SSH server during reload: %v", err)
			}
		}
	}

	return nil
}

// Stop gracefully stops the SSH server and cleans up resources.
// This method can be called programmatically to shutdown the server.
func (s *Server) Stop() error {
	s.getLogger().Info("Stopping SSH server...")

	// Trigger shutdown
	s.signalHandler.Shutdown()

	// Close the SSH server
	if sshServer := s.getSSH(); sshServer != nil {
		if err := sshServer.Close(); err != nil {
			s.getLogger().Errorf("Error closing SSH server: %v", err)
		}
	}

	// Stop metrics server if running
	if s.metricsServer != nil {
		if err := s.metricsServer.Stop(); err != nil {
			s.getLogger().Errorf("Error stopping metrics server: %v", err)
		} else {
			s.getLogger().Info("Metrics server stopped")
		}
	}

	// Stop signal handler
	s.signalHandler.Stop()

	s.getLogger().Info("SSH server stopped")
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
