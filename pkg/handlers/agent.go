// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This file implements SSH agent forwarding using gliderlabs/ssh's built-in
// server-side agent forwarding support (ssh.NewAgentListener /
// ssh.ForwardAgentConnections), which correctly opens auth-agent@openssh.com
// channels toward the client, matching the OpenSSH protocol direction.
package handlers

import (
	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// AgentHandler handles SSH agent forwarding functionality.
// Uses golang.org/x/crypto/ssh/agent for all agent protocol operations.
type AgentHandler struct {
	config *config.Config
	logger *logrus.Logger
}

// NewAgentHandler creates a new SSH agent forwarding handler.
// Uses library-first approach with golang.org/x/crypto/ssh/agent for all agent operations.
func NewAgentHandler(cfg *config.Config, logger *logrus.Logger) *AgentHandler {
	return &AgentHandler{
		config: cfg,
		logger: logger,
	}
}

// logf logs at the given level if a logger is configured, matching the
// nil-safe logging convention used by the other handlers in this package.
func (h *AgentHandler) logf(level logrus.Level, format string, args ...interface{}) {
	if h.logger == nil {
		return
	}
	h.logger.Logf(level, format, args...)
}

// CreateAgentForwardingHandler creates a defensive handler for inbound
// auth-agent@openssh.com channel-open requests.
//
// Per the SSH agent-forwarding protocol, the roles are the opposite of what
// registering a ChannelHandler for this type implies: it is the SERVER that
// opens auth-agent@openssh.com channels (via gossh.Conn.OpenChannel, see
// setupAgentForwarding/ssh.ForwardAgentConnections) whenever something on
// the server side wants to reach the client's forwarded agent; the CLIENT
// is the one that accepts those inbound channel-opens. A standards-compliant
// client never sends this server a channel-open of this type, so any
// inbound request here is either a misbehaving/malicious client or a
// misconfigured peer - it is rejected and logged rather than serviced.
func (h *AgentHandler) CreateAgentForwardingHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newCh gossh.NewChannel, ctx ssh.Context) {
		h.logf(logrus.WarnLevel, "Rejecting unexpected inbound auth-agent@openssh.com channel-open from user %s: the server, not the client, is expected to open this channel type", ctx.User())
		_ = newCh.Reject(gossh.Prohibited, "server does not accept inbound agent channels")
	}
}

// isAgentForwardingAllowed checks if agent forwarding is permitted for the given context.
// Checks both global configuration and per-key restrictions from authorized_keys.
func (h *AgentHandler) isAgentForwardingAllowed(ctx ssh.Context) bool {
	// Check global configuration
	if !h.config.AllowAgentForwarding {
		return false
	}

	// Check authorized key options if available
	if permissions := ctx.Permissions(); permissions != nil {
		if extensions := permissions.Extensions; extensions != nil {
			if noAgent, exists := extensions["no-agent-forwarding"]; exists && noAgent == "true" {
				return false
			}
		}
	}

	return true
}

// setupAgentForwarding prepares real SSH agent forwarding for an
// established session, if the client requested it via
// auth-agent-req@openssh.com (recorded by CreateAgentRequestHandler via
// ssh.SetAgentRequested). It delegates the actual forwarding protocol to
// gliderlabs/ssh's own ssh.NewAgentListener/ssh.ForwardAgentConnections,
// which correctly implement the server side: opening
// auth-agent@openssh.com channels toward the client for each connection
// accepted on a per-session Unix socket.
//
// It returns the SSH_AUTH_SOCK path to expose to the spawned shell/forced
// command, and a cleanup function that must run (e.g. via defer) when the
// session ends to stop forwarding and remove the temporary socket. If
// forwarding was not requested, or the listener cannot be created, it
// returns ("", a no-op cleanup) and the session proceeds exactly as if
// agent forwarding were absent.
func setupAgentForwarding(s ssh.Session, logger *logrus.Logger) (string, func()) {
	noop := func() {}
	if !ssh.AgentRequested(s) {
		return "", noop
	}

	l, err := ssh.NewAgentListener()
	if err != nil {
		if logger != nil {
			logger.Warnf("Failed to create agent forwarding listener for user %s: %v", s.User(), err)
		}
		return "", noop
	}

	go ssh.ForwardAgentConnections(l, s)

	return l.Addr().String(), func() { _ = l.Close() }
}

// CreateAgentRequestHandler creates a handler for agent forwarding requests.
// This handles auth-agent-req@openssh.com global requests to enable agent forwarding.
func (h *AgentHandler) CreateAgentRequestHandler() ssh.RequestHandler {
	return func(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
		user := ctx.User()
		h.logf(logrus.InfoLevel, "Agent forwarding request from user %s", user)

		// Check if agent forwarding is allowed
		if !h.isAgentForwardingAllowed(ctx) {
			h.logf(logrus.WarnLevel, "Agent forwarding request denied for user %s", user)
			return false, nil
		}

		// Record that the client requested forwarding so the session
		// handler (see setupAgentForwarding, called from shell.go) knows to
		// set up a listener and SSH_AUTH_SOCK for this session.
		ssh.SetAgentRequested(ctx)

		h.logf(logrus.InfoLevel, "Agent forwarding request approved for user %s", user)
		return true, nil
	}
}
