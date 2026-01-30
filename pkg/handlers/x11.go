// Package handlers provides SSH X11 forwarding functionality.
// X11 forwarding allows GUI applications to display on the client's X server
// through the SSH tunnel, maintaining security and encryption.
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// X11Handler manages X11 forwarding requests.
// Library choice: Standard library only (net, crypto/rand)
// Rationale: X11 forwarding in SSH is connection forwarding, not protocol implementation.
// The SSH server doesn't parse X11 protocol - it just forwards connections between
// the SSH channel and local X11 socket, similar to port forwarding.
type X11Handler struct {
	config *config.Config
	logger *logrus.Logger
	mu     sync.Mutex
	// displays maps session IDs to allocated display numbers
	displays map[string]int
}

// NewX11Handler creates a new X11 forwarding handler.
func NewX11Handler(cfg *config.Config, logger *logrus.Logger) *X11Handler {
	return &X11Handler{
		config:   cfg,
		logger:   logger,
		displays: make(map[string]int),
	}
}

// CreateX11RequestHandler creates an SSH request handler for X11 forwarding requests.
// Handles x11-req requests to establish X11 forwarding for a session.
func (h *X11Handler) CreateX11RequestHandler() ssh.RequestHandler {
	return func(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
		if req.Type != "x11-req" {
			return false, nil
		}

		// Check if X11 forwarding is allowed
		if !h.isX11ForwardingAllowed(ctx) {
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
				}).Warn("X11 forwarding request denied by configuration")
			}
			return false, nil
		}

		// Parse X11 request payload
		// Format: bool (single-connection), string (auth-protocol), string (auth-cookie), uint32 (screen-number)
		if len(req.Payload) < 1 {
			return false, nil
		}

		// For simplicity, we accept the request and will set up forwarding when x11 channels are opened
		// Store the request approval in context for later channel handling
		ctx.SetValue("x11-forwarding-enabled", true)

		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
			}).Info("X11 forwarding request approved")
		}

		return true, nil
	}
}

// CreateX11ChannelHandler creates an SSH channel handler for X11 forwarding channels.
// Handles x11 channels by forwarding connections to the local X11 server.
func (h *X11Handler) CreateX11ChannelHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		if newChan.ChannelType() != "x11" {
			newChan.Reject(gossh.UnknownChannelType, "unknown channel type")
			return
		}

		// Check if X11 forwarding was approved for this session
		if ctx.Value("x11-forwarding-enabled") != true {
			newChan.Reject(gossh.Prohibited, "X11 forwarding not enabled for this session")
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
				}).Warn("X11 channel rejected - forwarding not enabled")
			}
			return
		}

		// Accept the channel
		channel, requests, err := newChan.Accept()
		if err != nil {
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
					"error":     err,
				}).Error("Failed to accept X11 channel")
			}
			return
		}

		// Discard all requests on X11 channels (standard SSH behavior)
		go gossh.DiscardRequests(requests)

		// Connect to local X11 server
		x11Conn, err := h.connectToLocalX11()
		if err != nil {
			channel.Close()
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
					"error":     err,
				}).Error("Failed to connect to local X11 server")
			}
			return
		}

		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
			}).Info("X11 forwarding connection established")
		}

		// Forward data bidirectionally
		go h.forwardX11Data(channel, x11Conn, ctx)
	}
}

// isX11ForwardingAllowed checks if X11 forwarding is permitted for this session.
func (h *X11Handler) isX11ForwardingAllowed(ctx ssh.Context) bool {
	// Check global configuration
	if h.config == nil || !h.config.X11Forwarding {
		return false
	}

	// Check authorized_keys restrictions
	perms := ctx.Permissions()
	if perms != nil && perms.Permissions != nil {
		if _, ok := perms.Permissions.Extensions["no-x11-forwarding"]; ok {
			return false
		}
	}

	return true
}

// connectToLocalX11 establishes a connection to the local X11 server.
// Uses the DISPLAY environment variable to determine the X11 socket location.
func (h *X11Handler) connectToLocalX11() (net.Conn, error) {
	// Get DISPLAY environment variable
	display := os.Getenv("DISPLAY")
	if display == "" {
		return nil, fmt.Errorf("DISPLAY environment variable not set")
	}

	// Parse display using the correct ParseDisplayNumber function
	host, displayNum, _, err := ParseDisplayNumber(display)
	if err != nil {
		return nil, fmt.Errorf("invalid DISPLAY format %q: %w", display, err)
	}

	// Connect to X11 server
	// Try Unix socket first (most common for local connections)
	socketPath := fmt.Sprintf("/tmp/.X11-unix/X%d", displayNum)
	conn, err := net.Dial("unix", socketPath)
	if err == nil {
		return conn, nil
	}

	// Fall back to TCP connection if Unix socket fails
	if host == "" {
		host = "localhost"
	}
	tcpAddr := fmt.Sprintf("%s:%d", host, 6000+displayNum)
	conn, err = net.Dial("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to X11 server: %w", err)
	}

	return conn, nil
}

// forwardX11Data handles bidirectional data forwarding between SSH channel and X11 connection.
func (h *X11Handler) forwardX11Data(channel gossh.Channel, x11Conn net.Conn, ctx ssh.Context) {
	defer channel.Close()
	defer x11Conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Channel -> X11 server
	go func() {
		defer wg.Done()
		n, err := io.Copy(x11Conn, channel)
		if err != nil && h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
				"direction": "channel->x11",
				"bytes":     n,
				"error":     err,
			}).Debug("X11 forwarding copy completed")
		}
	}()

	// X11 server -> Channel
	go func() {
		defer wg.Done()
		n, err := io.Copy(channel, x11Conn)
		if err != nil && h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
				"direction": "x11->channel",
				"bytes":     n,
				"error":     err,
			}).Debug("X11 forwarding copy completed")
		}
	}()

	wg.Wait()

	if h.logger != nil {
		h.logger.WithFields(logrus.Fields{
			"user":      ctx.User(),
			"sessionID": ctx.SessionID(),
		}).Info("X11 forwarding connection closed")
	}
}

// AllocateDisplay allocates a display number for X11 forwarding.
// Returns the display number and a cleanup function to release it.
func (h *X11Handler) AllocateDisplay(sessionID string) (int, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find available display starting from X11DisplayOffset
	offset := 10 // Default OpenSSH value
	if h.config != nil && h.config.X11DisplayOffset > 0 {
		offset = h.config.X11DisplayOffset
	}

	// Simple allocation: find first unused display
	display := offset
	for {
		inUse := false
		for _, d := range h.displays {
			if d == display {
				inUse = true
				break
			}
		}
		if !inUse {
			break
		}
		display++
	}

	h.displays[sessionID] = display

	cleanup := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.displays, sessionID)
	}

	return display, cleanup
}

// GenerateX11Cookie generates a random X11 authentication cookie.
// Uses crypto/rand for secure random generation.
func GenerateX11Cookie() (string, error) {
	// X11 MIT-MAGIC-COOKIE-1 is 128 bits (16 bytes)
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return "", fmt.Errorf("failed to generate X11 cookie: %w", err)
	}
	return hex.EncodeToString(cookie), nil
}

// ParseDisplayNumber parses a DISPLAY environment variable value.
// Returns host, display number, and screen number.
func ParseDisplayNumber(display string) (host string, displayNum, screenNum int, err error) {
	// Default values
	host = ""
	displayNum = 0
	screenNum = 0

	if display == "" {
		err = fmt.Errorf("empty display string")
		return
	}

	// Parse format: [host]:display[.screen]
	// Examples: :0, :0.0, localhost:10, localhost:10.0

	// Split by screen separator if present
	parts := display
	if idx := strings.LastIndex(display, "."); idx >= 0 {
		// Check if what follows the dot is a number
		if snum, serr := strconv.Atoi(display[idx+1:]); serr == nil {
			screenNum = snum
			parts = display[:idx]
		}
	}

	// Parse host and display
	colonIdx := strings.LastIndex(parts, ":")
	if colonIdx < 0 {
		err = fmt.Errorf("invalid display format: missing colon")
		return
	}

	if colonIdx == 0 {
		// Unix socket format: :N
		displayNum, err = strconv.Atoi(parts[1:])
	} else {
		// TCP format: hostname:N
		host = parts[:colonIdx]
		displayNum, err = strconv.Atoi(parts[colonIdx+1:])
	}

	return
}
