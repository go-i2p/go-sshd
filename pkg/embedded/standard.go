// Package embedded provides an embeddable SSH server interface.
package embedded

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/crypto"
	"github.com/go-i2p/go-sshd/pkg/handlers"
	"github.com/go-i2p/go-sshd/pkg/logging"
)

// StandardEmbeddedSSHServer is the standard implementation of EmbeddedSSHServer.
// It wraps gliderlabs/ssh and reuses existing pkg/server, pkg/handlers, pkg/crypto components.
type StandardEmbeddedSSHServer struct {
	listener net.Listener
	opts     ConfigOptions
	ssh      *ssh.Server
	logger   *logrus.Logger
	mu       sync.RWMutex
	started  bool
	stopOnce sync.Once
}

// NewStandardEmbeddedSSHServer creates a new standard embedded SSH server.
// The listener parameter provides the network connection source.
// Returns error if listener is nil or configuration is invalid.
func NewStandardEmbeddedSSHServer(listener net.Listener, opts ConfigOptions) (EmbeddedSSHServer, error) {
	if listener == nil {
		return nil, fmt.Errorf("listener is required")
	}

	// Apply defaults for nil config sections
	if opts.Authentication == nil {
		opts.Authentication = DefaultAuthenticationConfig()
	}
	if opts.Session == nil {
		opts.Session = DefaultSessionConfig()
	}
	if opts.Logging == nil {
		opts.Logging = DefaultLoggingConfig()
	}
	if opts.Forwarding == nil {
		opts.Forwarding = DefaultForwardingConfig()
	}

	opts.Listener = listener

	server := &StandardEmbeddedSSHServer{
		listener: listener,
		opts:     opts,
	}

	// Configure the server with initial options
	if err := server.Configure(opts); err != nil {
		return nil, fmt.Errorf("initial configuration failed: %w", err)
	}

	return server, nil
}

// Configure applies configuration options to the server.
// Must be called before Start(). Can be called multiple times to update configuration.
func (s *StandardEmbeddedSSHServer) Configure(opts ConfigOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("cannot reconfigure server after Start() has been called")
	}

	// Validate and set listener
	if opts.Listener != nil {
		s.listener = opts.Listener
	}
	if s.listener == nil {
		return fmt.Errorf("listener is required")
	}

	// Apply configuration defaults
	s.opts = opts
	if s.opts.Authentication == nil {
		s.opts.Authentication = DefaultAuthenticationConfig()
	}
	if s.opts.Session == nil {
		s.opts.Session = DefaultSessionConfig()
	}
	if s.opts.Logging == nil {
		s.opts.Logging = DefaultLoggingConfig()
	}
	if s.opts.Forwarding == nil {
		s.opts.Forwarding = DefaultForwardingConfig()
	}

	// Initialize logger
	if err := s.initLogger(); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize SSH server
	if err := s.initSSHServer(); err != nil {
		return fmt.Errorf("failed to initialize SSH server: %w", err)
	}

	return nil
}

// initLogger initializes the logger from configuration.
func (s *StandardEmbeddedSSHServer) initLogger() error {
	if s.opts.Logging.Logger != nil {
		s.logger = s.opts.Logging.Logger
		return nil
	}

	// Convert embedded config to pkg/config format for logger creation
	cfg := &config.Config{
		LogLevel:       s.opts.Logging.Level,
		SyslogFacility: s.opts.Logging.SyslogFacility,
		LogFile:        s.opts.Logging.LogFile,
	}

	logger, err := logging.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	s.logger = logger.GetLogrus()
	return nil
}

// initSSHServer initializes the gliderlabs/ssh server with current configuration.
func (s *StandardEmbeddedSSHServer) initSSHServer() error {
	// Create gliderlabs/ssh server
	sshServer := &ssh.Server{
		Addr: s.listener.Addr().String(),
	}

	// Configure host keys
	if err := s.configureHostKeys(sshServer); err != nil {
		return fmt.Errorf("failed to configure host keys: %w", err)
	}

	// Configure authentication handlers
	if err := s.configureAuthentication(sshServer); err != nil {
		return fmt.Errorf("failed to configure authentication: %w", err)
	}

	// Configure session handlers
	if err := s.configureSession(sshServer); err != nil {
		return fmt.Errorf("failed to configure session: %w", err)
	}

	// Configure forwarding handlers
	if err := s.configureForwarding(sshServer); err != nil {
		return fmt.Errorf("failed to configure forwarding: %w", err)
	}

	s.ssh = sshServer
	return nil
}

// configureHostKeys sets up SSH host keys for the server.
func (s *StandardEmbeddedSSHServer) configureHostKeys(sshServer *ssh.Server) error {
	var hostKeyPaths []string

	// Use provided paths
	if len(s.opts.HostKeys.Paths) > 0 {
		hostKeyPaths = s.opts.HostKeys.Paths
	}

	// Handle in-memory key data
	if len(s.opts.HostKeys.Data) > 0 {
		for i, keyData := range s.opts.HostKeys.Data {
			signer, err := gossh.ParsePrivateKey(keyData)
			if err != nil {
				s.logger.Warnf("Failed to parse in-memory host key %d: %v", i, err)
				continue
			}
			if err := crypto.ValidateHostKey(signer); err != nil {
				s.logger.Warnf("Invalid in-memory host key %d: %v", i, err)
				continue
			}
			sshServer.AddHostKey(signer)
			fingerprint := crypto.GetKeyFingerprint(signer.PublicKey())
			keyType := crypto.GetKeyType(signer.PublicKey())
			s.logger.Infof("Loaded in-memory host key: %s %s", keyType, fingerprint)
		}
	}

	// Load host keys from paths or auto-generate
	if len(hostKeyPaths) > 0 || s.opts.HostKeys.AutoGenerate {
		hostKeyManager := crypto.NewHostKeyManager(hostKeyPaths)
		signers, err := hostKeyManager.LoadOrGenerateKeys()
		if err != nil {
			return fmt.Errorf("failed to load or generate host keys: %w", err)
		}

		for i, signer := range signers {
			if err := crypto.ValidateHostKey(signer); err != nil {
				s.logger.Warnf("Invalid host key %d: %v", i, err)
				continue
			}
			sshServer.AddHostKey(signer)
			fingerprint := crypto.GetKeyFingerprint(signer.PublicKey())
			keyType := crypto.GetKeyType(signer.PublicKey())
			s.logger.Infof("Loaded host key: %s %s", keyType, fingerprint)
		}
	}

	// Verify at least one key was loaded
	if len(sshServer.HostSigners) == 0 {
		return fmt.Errorf("no valid host keys configured")
	}

	return nil
}

// configureAuthentication sets up SSH authentication handlers.
func (s *StandardEmbeddedSSHServer) configureAuthentication(sshServer *ssh.Server) error {
	authCfg := s.opts.Authentication

	// Convert embedded config to pkg/config format for handlers
	cfg := &config.Config{
		PasswordAuthentication:       authCfg.PasswordAuth,
		PubkeyAuthentication:         authCfg.PublicKeyAuth,
		KbdInteractiveAuthentication: authCfg.KeyboardInteractiveAuth,
		AuthorizedKeysFile:           authCfg.AuthorizedKeysFiles,
		TrustedUserCAKeys:            authCfg.TrustedUserCAKeys,
		RevokedKeys:                  authCfg.RevokedKeys,
		PermitRootLogin:              s.opts.Session.PermitRootLogin,
		AllowUsers:                   s.opts.Session.AllowUsers,
		DenyUsers:                    s.opts.Session.DenyUsers,
	}

	// Create authentication handler
	authHandler := handlers.NewAuthHandler(cfg, s.logger)

	// Configure password authentication
	if authCfg.PasswordAuth {
		if authCfg.CustomPasswordHandler != nil {
			sshServer.PasswordHandler = s.wrapCustomPasswordHandler(authCfg.CustomPasswordHandler)
		} else {
			sshServer.PasswordHandler = authHandler.CreatePasswordHandler()
		}
	}

	// Configure public key authentication
	if authCfg.PublicKeyAuth || authCfg.CertificateAuth {
		if authCfg.CustomPublicKeyHandler != nil {
			sshServer.PublicKeyHandler = s.wrapCustomPublicKeyHandlerGossh(authCfg.CustomPublicKeyHandler)
		} else {
			sshServer.PublicKeyHandler = authHandler.CreatePublicKeyHandler()
		}
	}

	// Configure keyboard-interactive authentication
	if authCfg.KeyboardInteractiveAuth {
		sshServer.KeyboardInteractiveHandler = authHandler.CreateKeyboardInteractiveHandler()
	}

	return nil
}

// wrapCustomPasswordHandler wraps a custom password handler for gliderlabs/ssh compatibility.
func (s *StandardEmbeddedSSHServer) wrapCustomPasswordHandler(handler func(context.Context, string) error) ssh.PasswordHandler {
	return func(ctx ssh.Context, password string) bool {
		if err := handler(ctx, password); err != nil {
			s.logger.Debugf("Custom password handler rejected: %v", err)
			return false
		}
		return true
	}
}

// wrapCustomPublicKeyHandler wraps a custom public key handler for gliderlabs/ssh compatibility.
func (s *StandardEmbeddedSSHServer) wrapCustomPublicKeyHandler(handler func(context.Context, ssh.PublicKey) error) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		if err := handler(ctx, key); err != nil {
			s.logger.Debugf("Custom public key handler rejected: %v", err)
			return false
		}
		return true
	}
}

// wrapCustomPublicKeyHandlerGossh wraps a custom public key handler (with gossh.PublicKey) for gliderlabs/ssh compatibility.
func (s *StandardEmbeddedSSHServer) wrapCustomPublicKeyHandlerGossh(handler func(context.Context, gossh.PublicKey) error) ssh.PublicKeyHandler {
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		if err := handler(ctx, key); err != nil {
			s.logger.Debugf("Custom public key handler rejected: %v", err)
			return false
		}
		return true
	}
}

// configureSession sets up SSH session handling.
func (s *StandardEmbeddedSSHServer) configureSession(sshServer *ssh.Server) error {
	sessionCfg := s.opts.Session

	// Configure shell handler
	if sessionCfg.CustomSessionHandler != nil {
		sshServer.Handler = s.wrapCustomSessionHandler(sessionCfg.CustomSessionHandler)
	} else {
		shellHandler := handlers.NewShellHandler(s.logger)
		sshServer.Handler = shellHandler.CreateSessionHandler()
	}

	// Configure SFTP subsystem
	if sessionCfg.SFTPEnabled {
		cfg := &config.Config{
			Subsystem: map[string]string{
				"sftp": "internal-sftp",
			},
		}
		sftpHandler := handlers.NewSFTPHandler(cfg, s.logger)
		sshServer.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler.CreateSubsystemHandler(),
		}
		s.logger.Info("SFTP subsystem enabled")
	}

	return nil
}

// wrapCustomSessionHandler wraps a custom session handler for gliderlabs/ssh compatibility.
func (s *StandardEmbeddedSSHServer) wrapCustomSessionHandler(handler func(Session) error) ssh.Handler {
	return func(sess ssh.Session) {
		wrapper := &sessionWrapper{sess: sess}
		if err := handler(wrapper); err != nil {
			s.logger.Errorf("Custom session handler error: %v", err)
		}
	}
}

// sessionWrapper adapts gliderlabs/ssh.Session to embedded.Session interface.
type sessionWrapper struct {
	sess ssh.Session
}

func (w *sessionWrapper) User() string         { return w.sess.User() }
func (w *sessionWrapper) RemoteAddr() net.Addr { return w.sess.RemoteAddr() }
func (w *sessionWrapper) Command() []string    { return w.sess.Command() }
func (w *sessionWrapper) Environ() []string    { return w.sess.Environ() }
func (w *sessionWrapper) Pty() *PtyRequest {
	ptyReq, _, ok := w.sess.Pty()
	if !ok {
		return nil
	}
	return &PtyRequest{
		Term:   ptyReq.Term,
		Width:  ptyReq.Window.Width,
		Height: ptyReq.Window.Height,
	}
}

// configureForwarding sets up port forwarding and agent forwarding.
func (s *StandardEmbeddedSSHServer) configureForwarding(sshServer *ssh.Server) error {
	fwdCfg := s.opts.Forwarding

	// Convert embedded config to pkg/config format for handlers
	cfg := &config.Config{
		AllowTcpForwarding:   fwdCfg.AllowTCPForwarding,
		AllowAgentForwarding: fwdCfg.AllowAgentForwarding,
		X11Forwarding:        fwdCfg.AllowX11Forwarding,
		X11DisplayOffset:     fwdCfg.X11DisplayOffset,
		X11UseLocalhost:      fwdCfg.X11UseLocalhost,
		GatewayPorts:         fwdCfg.GatewayPorts,
	}

	// Configure TCP port forwarding
	if fwdCfg.AllowTCPForwarding {
		forwardingHandler := handlers.NewForwardingHandler(cfg, s.logger)

		sshServer.LocalPortForwardingCallback = forwardingHandler.CreateLocalPortForwardHandler()
		sshServer.ReversePortForwardingCallback = forwardingHandler.CreateReversePortForwardHandler()

		if sshServer.ChannelHandlers == nil {
			sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
		}
		sshServer.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler

		if sshServer.RequestHandlers == nil {
			sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
		}
		tcpHandler := forwardingHandler.GetTCPHandler()
		sshServer.RequestHandlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
		sshServer.RequestHandlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest

		s.logger.Info("TCP port forwarding enabled")
	}

	// Configure agent forwarding
	if fwdCfg.AllowAgentForwarding {
		agentHandler := handlers.NewAgentHandler(cfg, s.logger)

		if sshServer.ChannelHandlers == nil {
			sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
		}
		sshServer.ChannelHandlers["auth-agent@openssh.com"] = agentHandler.CreateAgentForwardingHandler()

		if sshServer.RequestHandlers == nil {
			sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
		}
		sshServer.RequestHandlers["auth-agent-req@openssh.com"] = agentHandler.CreateAgentRequestHandler()

		s.logger.Info("SSH agent forwarding enabled")
	}

	// Configure X11 forwarding
	if fwdCfg.AllowX11Forwarding {
		x11Handler := handlers.NewX11Handler(cfg, s.logger)

		if sshServer.ChannelHandlers == nil {
			sshServer.ChannelHandlers = make(map[string]ssh.ChannelHandler)
		}
		sshServer.ChannelHandlers["x11"] = x11Handler.CreateX11ChannelHandler()

		if sshServer.RequestHandlers == nil {
			sshServer.RequestHandlers = make(map[string]ssh.RequestHandler)
		}
		sshServer.RequestHandlers["x11-req"] = x11Handler.CreateX11RequestHandler()

		s.logger.WithFields(logrus.Fields{
			"displayOffset": fwdCfg.X11DisplayOffset,
			"useLocalhost":  fwdCfg.X11UseLocalhost,
		}).Info("X11 forwarding enabled")
	}

	return nil
}

// Start begins accepting SSH connections on the provided listener.
// Blocks until Stop() is called or an error occurs.
func (s *StandardEmbeddedSSHServer) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	if s.ssh == nil {
		s.mu.Unlock()
		return fmt.Errorf("server not configured")
	}
	s.started = true
	s.mu.Unlock()

	s.logger.Infof("Starting embedded SSH server on %s", s.listener.Addr())

	// Use the provided listener instead of creating a new one
	return s.ssh.Serve(s.listener)
}

// Stop initiates graceful shutdown with context timeout.
// Waits for active connections to close or context deadline.
func (s *StandardEmbeddedSSHServer) Stop(ctx context.Context) error {
	s.mu.RLock()
	if !s.started {
		s.mu.RUnlock()
		return fmt.Errorf("server not started")
	}
	sshServer := s.ssh
	if sshServer == nil {
		s.mu.RUnlock()
		return fmt.Errorf("server not initialized")
	}
	s.mu.RUnlock()

	var err error
	s.stopOnce.Do(func() {
		s.logger.Info("Stopping embedded SSH server")

		// Create channel to signal shutdown completion
		done := make(chan error, 1)

		go func() {
			done <- sshServer.Close()
		}()

		// Wait for shutdown or context timeout
		select {
		case err = <-done:
			if err != nil {
				s.logger.Warnf("Server shutdown error: %v", err)
			} else {
				s.logger.Info("Server shutdown complete")
			}
		case <-ctx.Done():
			err = fmt.Errorf("shutdown timeout: %w", ctx.Err())
			s.logger.Warnf("Server shutdown timeout: %v", err)
		}
	})

	return err
}

// Cleanup releases all server resources (host keys, file handles, etc.).
// Should be called after Stop() completes.
func (s *StandardEmbeddedSSHServer) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Cleaning up embedded SSH server resources")

	// Clear server references to allow garbage collection
	s.ssh = nil
	s.listener = nil

	return nil
}
