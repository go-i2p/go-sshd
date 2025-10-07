// Package handlers provides SSH protocol handlers for port forwarding.
// This package implements local, remote, and dynamic port forwarding using gliderlabs/ssh.
package handlers

import (
	"fmt"
	"net"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// ForwardingHandler handles SSH port forwarding functionality.
// Implements local (-L), remote (-R), and dynamic (-D) port forwarding using gliderlabs/ssh.
type ForwardingHandler struct {
	config     *config.Config
	logger     *logrus.Logger
	tcpHandler *ssh.ForwardedTCPHandler
}

// NewForwardingHandler creates a new port forwarding handler.
// Uses library-first approach with gliderlabs/ssh for all forwarding operations.
func NewForwardingHandler(cfg *config.Config, logger *logrus.Logger) *ForwardingHandler {
	return &ForwardingHandler{
		config:     cfg,
		logger:     logger,
		tcpHandler: &ssh.ForwardedTCPHandler{},
	}
}

// CreateLocalPortForwardHandler creates a local port forwarding handler for gliderlabs/ssh.
// Implements SSH local port forwarding (-L option) using built-in callback.
func (h *ForwardingHandler) CreateLocalPortForwardHandler() ssh.LocalPortForwardingCallback {
	return func(ctx ssh.Context, dstHost string, dstPort uint32) bool {
		user := ctx.User()
		dstAddr := fmt.Sprintf("%s:%d", dstHost, dstPort)

		h.logger.Infof("Local port forwarding request from user %s to %s", user, dstAddr)

		// Check if forwarding is allowed by configuration
		if !h.isForwardingAllowed(user, "local", dstHost, dstPort) {
			h.logger.Warnf("Local port forwarding denied for user %s to %s:%d",
				user, dstHost, dstPort)
			return false
		}

		h.logger.Infof("Local port forwarding allowed for user %s to %s", user, dstAddr)
		return true
	}
}

// CreateReversePortForwardHandler creates a reverse port forwarding handler for gliderlabs/ssh.
// Implements SSH remote port forwarding (-R option) using built-in callback.
func (h *ForwardingHandler) CreateReversePortForwardHandler() ssh.ReversePortForwardingCallback {
	return func(ctx ssh.Context, host string, port uint32) bool {
		user := ctx.User()
		bindAddr := fmt.Sprintf("%s:%d", host, port)

		h.logger.Infof("Remote port forwarding request from user %s for %s", user, bindAddr)

		// Check if reverse forwarding is allowed
		if !h.isForwardingAllowed(user, "remote", host, port) {
			h.logger.Warnf("Remote port forwarding denied for user %s for %s:%d",
				user, host, port)
			return false
		}

		// Check if bind address is allowed
		if !h.isBindAddressAllowed(host) {
			h.logger.Warnf("Remote port forwarding bind address %s not allowed for user %s",
				host, user)
			return false
		}

		h.logger.Infof("Remote port forwarding allowed for user %s for %s", user, bindAddr)
		return true
	}
}

// GetTCPHandler returns the ForwardedTCPHandler for request handling.
// This handler should be registered for "tcpip-forward" and "cancel-tcpip-forward" requests.
func (h *ForwardingHandler) GetTCPHandler() *ssh.ForwardedTCPHandler {
	return h.tcpHandler
}

// isForwardingAllowed checks if port forwarding is allowed for the given parameters.
// Implements basic security checks based on configuration and user permissions.
func (h *ForwardingHandler) isForwardingAllowed(user, forwardType, host string, port uint32) bool {
	// Check global forwarding settings
	switch forwardType {
	case "local":
		if !h.config.AllowTcpForwarding {
			return false
		}
		// For local forwarding, check if target host is allowed
		if !h.isTargetHostAllowed(host) {
			return false
		}
	case "remote":
		if !h.config.AllowTcpForwarding {
			return false
		}
		// For remote forwarding, the host is a bind address, not a target host
		// Don't apply target host restrictions to bind addresses
	default:
		return false
	}

	// Check if target port is in restricted range (below 1024 for non-root)
	if port < 1024 && user != "root" {
		h.logger.Debugf("Privileged port %d denied for non-root user %s", port, user)
		return false
	}

	return true
}

// isBindAddressAllowed checks if the bind address is allowed for remote forwarding.
// Implements security checks for which addresses can be bound for reverse forwarding.
func (h *ForwardingHandler) isBindAddressAllowed(host string) bool {
	// Allow localhost addresses
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}

	// Allow empty host (bind to all interfaces) if configured
	if host == "" || host == "*" {
		return h.config.GatewayPorts
	}

	// Allow specific interface addresses if GatewayPorts is enabled
	if h.config.GatewayPorts {
		// Parse as IP address to validate
		if net.ParseIP(host) != nil {
			return true
		}
	}

	return false
}

// isTargetHostAllowed checks if connections to the target host are allowed.
// Implements basic security policy for outbound connections.
func (h *ForwardingHandler) isTargetHostAllowed(host string) bool {
	// Block connections to obviously restricted addresses
	restrictedHosts := []string{
		"169.254.169.254",          // AWS metadata service
		"metadata.google.internal", // GCP metadata service
	}

	for _, restricted := range restrictedHosts {
		if host == restricted {
			return false
		}
	}

	// Allow localhost connections
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}

	// Parse as IP to check for private ranges
	ip := net.ParseIP(host)
	if ip != nil {
		// Allow localhost variants
		if ip.IsLoopback() {
			return true
		}
		// Allow private networks (could be configurable)
		if ip.IsPrivate() {
			return true
		}
		// Allow public IPs (could be configurable)
		return true
	}

	// Allow domain names (basic validation)
	if len(host) > 0 && len(host) <= 253 {
		return true
	}

	return false
}
