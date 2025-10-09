// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This file implements SSH agent forwarding using golang.org/x/crypto/ssh/agent.
package handlers

import (
	"fmt"
	"io"
	"net"
	"os"

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

// CreateAgentForwardingHandler creates an SSH agent forwarding channel handler.
// This handler processes auth-agent@openssh.com channel requests following OpenSSH protocol.
func (h *AgentHandler) CreateAgentForwardingHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newCh gossh.NewChannel, ctx ssh.Context) {
		user := ctx.User()
		h.logger.Infof("Agent forwarding channel request from user %s", user)

		// Check if agent forwarding is allowed by configuration
		if !h.isAgentForwardingAllowed(ctx) {
			h.logger.Warnf("Agent forwarding denied for user %s", user)
			_ = newCh.Reject(gossh.Prohibited, "agent forwarding disabled")
			return
		}

		// Accept the channel
		channel, requests, err := newCh.Accept()
		if err != nil {
			h.logger.Errorf("Failed to accept agent forwarding channel for user %s: %v", user, err)
			return
		}
		defer channel.Close()

		h.logger.Infof("Agent forwarding channel established for user %s", user)

		// Connect to local SSH agent
		agentConn, err := h.connectToLocalAgent()
		if err != nil {
			h.logger.Errorf("Failed to connect to local SSH agent for user %s: %v", user, err)
			return
		}
		defer agentConn.Close()

		// Handle channel in background
		go h.handleAgentChannel(channel, agentConn, user)

		// Discard requests on this channel (agent channels don't typically have requests)
		go gossh.DiscardRequests(requests)
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

// connectToLocalAgent establishes a connection to the local SSH agent.
// This connects to the SSH_AUTH_SOCK socket following OpenSSH conventions.
func (h *AgentHandler) connectToLocalAgent() (net.Conn, error) {
	// Get SSH agent socket path from environment
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set - no agent available")
	}

	// Connect to the Unix domain socket
	conn, err := net.Dial("unix", authSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent socket %s: %w", authSock, err)
	}

	return conn, nil
}

// handleAgentChannel handles bidirectional communication between SSH channel and local agent.
// This function copies data between the SSH channel and agent connection using standard Go patterns.
func (h *AgentHandler) handleAgentChannel(channel gossh.Channel, agentConn net.Conn, user string) {
	h.logger.Debugf("Starting agent forwarding proxy for user %s", user)

	// Create error channel to handle goroutine completion
	done := make(chan error, 2)

	// Copy data from channel to agent
	go func() {
		_, err := h.copyData(agentConn, channel, "channel->agent", user)
		done <- err
	}()

	// Copy data from agent to channel
	go func() {
		_, err := h.copyData(channel, agentConn, "agent->channel", user)
		done <- err
	}()

	// Wait for either direction to complete or error
	err := <-done
	if err != nil {
		h.logger.Debugf("Agent forwarding ended for user %s: %v", user, err)
	} else {
		h.logger.Debugf("Agent forwarding completed for user %s", user)
	}
}

// copyData copies data between two connections with logging.
// Uses standard io.Copy pattern for efficient data transfer.
func (h *AgentHandler) copyData(dst, src io.ReadWriter, direction, user string) (int64, error) {
	h.logger.Debugf("Starting data copy %s for user %s", direction, user)

	// Use io.Copy for efficient data transfer
	n, err := io.Copy(dst, src)
	if err != nil {
		h.logger.Debugf("Data copy %s for user %s ended with error: %v", direction, user, err)
	} else {
		h.logger.Debugf("Data copy %s for user %s completed, transferred %d bytes", direction, user, n)
	}

	return n, err
}

// CreateAgentRequestHandler creates a handler for agent forwarding requests.
// This handles auth-agent-req@openssh.com global requests to enable agent forwarding.
func (h *AgentHandler) CreateAgentRequestHandler() ssh.RequestHandler {
	return func(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
		user := ctx.User()
		h.logger.Infof("Agent forwarding request from user %s", user)

		// Check if agent forwarding is allowed
		if !h.isAgentForwardingAllowed(ctx) {
			h.logger.Warnf("Agent forwarding request denied for user %s", user)
			return false, nil
		}

		h.logger.Infof("Agent forwarding request approved for user %s", user)
		return true, nil
	}
}
