// Package server provides the core SSH server implementation.
// This package wraps gliderlabs/ssh to create an OpenSSH-compatible server.
package server

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gliderlabs/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/crypto"
	"github.com/go-i2p/go-sshd/pkg/handlers"
	"github.com/go-i2p/go-sshd/pkg/logging"
)

// Server wraps gliderlabs/ssh with OpenSSH-compatible configuration.
// This is a thin wrapper that coordinates library functionality.
type Server struct {
	config *config.Config
	ssh    *ssh.Server
	logger *logging.Logger
}

// New creates a new SSH server with the given configuration.
// This function integrates gliderlabs/ssh with our configuration system.
func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	// Create centralized logger from configuration
	logger, err := logging.NewLogger(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create gliderlabs/ssh server with basic options
	sshServer := &ssh.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
	}

	// Configure host keys using the new HostKeyManager
	hostKeyManager := crypto.NewHostKeyManager(cfg.HostKey)
	signers, err := hostKeyManager.LoadOrGenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load or generate host keys: %w", err)
	}

	// Add all signers to the SSH server
	for i, signer := range signers {
		if err := crypto.ValidateHostKey(signer); err != nil {
			logger.Errorf("Invalid host key %d: %v", i, err)
			continue
		}

		sshServer.AddHostKey(signer)
		fingerprint := crypto.GetKeyFingerprint(signer.PublicKey())
		keyType := crypto.GetKeyType(signer.PublicKey())
		logger.Infof("Loaded host key: %s %s", keyType, fingerprint)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no valid host keys loaded")
	}

	// Configure authentication handlers using the new AuthHandler
	if cfg.PasswordAuthentication || cfg.PubkeyAuthentication {
		authHandler := handlers.NewAuthHandler(cfg, logger.GetLogrus())
		sshServer.PasswordHandler = authHandler.CreatePasswordHandler()
		sshServer.PublicKeyHandler = authHandler.CreatePublicKeyHandler()
	}

	// Configure session handler using the new ShellHandler
	shellHandler := handlers.NewShellHandler(logger.GetLogrus())
	sshServer.Handler = shellHandler.CreateSessionHandler()

	// Configure SFTP subsystem handler
	sftpHandler := handlers.NewSFTPHandler(cfg, logger.GetLogrus())
	sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
		"sftp": sftpHandler.CreateSubsystemHandler(),
	}

	// Configure port forwarding handlers if TCP forwarding is enabled
	if cfg.AllowTcpForwarding {
		forwardingHandler := handlers.NewForwardingHandler(cfg, logger.GetLogrus())

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
