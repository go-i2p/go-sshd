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

// x11SessionStateKey is the ssh.Context value key under which the per-session
// X11 forwarding state (allocated display, negotiated auth) is stored after a
// successful x11-req request, for later use by the x11 channel handler.
const x11SessionStateKey = "x11-session-state"

// x11ReqPayload is the RFC 4254 §6.3.1 "x11-req" request payload.
type x11ReqPayload struct {
	SingleConnection bool
	AuthProtocol     string
	AuthCookie       string
	ScreenNumber     uint32
}

// x11SessionState holds the per-session X11 forwarding state negotiated via
// the x11-req request. It is used to select the correct local X11 display
// when an x11 channel is later opened for this session, instead of relying
// on the sshd process's own $DISPLAY.
type x11SessionState struct {
	display      int
	authProtocol string
	authCookie   string
	screenNumber int
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

		// Parse the x11-req payload: single-connection flag, auth protocol,
		// auth cookie, and screen number (RFC 4254 §6.3.1).
		var payload x11ReqPayload
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
					"error":     err,
				}).Warn("Failed to parse x11-req payload")
			}
			return false, nil
		}

		// Allocate a per-session display and release it when the session ends.
		display, cleanup := h.AllocateDisplay(ctx.SessionID())
		go func() {
			<-ctx.Done()
			cleanup()
		}()

		ctx.SetValue(x11SessionStateKey, &x11SessionState{
			display:      display,
			authProtocol: payload.AuthProtocol,
			authCookie:   payload.AuthCookie,
			screenNumber: int(payload.ScreenNumber),
		})
		ctx.SetValue("x11-forwarding-enabled", true)

		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
				"display":   display,
			}).Info("X11 forwarding request approved")
		}

		return true, nil
	}
}

// CreateX11ChannelHandler creates an SSH channel handler for X11 forwarding channels.
// Handles x11 channels by forwarding connections to the local X11 server.
func (h *X11Handler) CreateX11ChannelHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		if !h.validateX11Channel(newChan, ctx) {
			return
		}

		state, ok := ctx.Value(x11SessionStateKey).(*x11SessionState)
		if !ok || state == nil {
			newChan.Reject(gossh.ConnectionFailed, "no X11 display allocated for this session")
			if h.logger != nil {
				h.logger.WithFields(logrus.Fields{
					"user":      ctx.User(),
					"sessionID": ctx.SessionID(),
				}).Error("X11 channel opened without a prior successful x11-req")
			}
			return
		}

		channel, requests, err := h.acceptX11Channel(newChan, ctx)
		if err != nil {
			return
		}

		// Discard all requests on X11 channels (standard SSH behavior)
		go gossh.DiscardRequests(requests)

		x11Conn, err := h.connectAndLogX11(ctx, state.display)
		if err != nil {
			channel.Close()
			return
		}

		h.logX11Established(ctx)
		go h.forwardX11Data(channel, x11Conn, ctx)
	}
}

// validateX11Channel checks if the channel is valid and X11 forwarding is enabled.
func (h *X11Handler) validateX11Channel(newChan gossh.NewChannel, ctx ssh.Context) bool {
	if newChan.ChannelType() != "x11" {
		newChan.Reject(gossh.UnknownChannelType, "unknown channel type")
		return false
	}

	if ctx.Value("x11-forwarding-enabled") != true {
		newChan.Reject(gossh.Prohibited, "X11 forwarding not enabled for this session")
		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
			}).Warn("X11 channel rejected - forwarding not enabled")
		}
		return false
	}

	return true
}

// acceptX11Channel accepts an X11 channel request and returns the channel.
func (h *X11Handler) acceptX11Channel(newChan gossh.NewChannel, ctx ssh.Context) (gossh.Channel, <-chan *gossh.Request, error) {
	channel, requests, err := newChan.Accept()
	if err != nil {
		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
				"error":     err,
			}).Error("Failed to accept X11 channel")
		}
		return nil, nil, err
	}
	return channel, requests, nil
}

// connectAndLogX11 connects to the local X11 server for the session's
// allocated display and logs any errors.
func (h *X11Handler) connectAndLogX11(ctx ssh.Context, display int) (net.Conn, error) {
	x11Conn, err := h.connectToLocalX11(display)
	if err != nil {
		if h.logger != nil {
			h.logger.WithFields(logrus.Fields{
				"user":      ctx.User(),
				"sessionID": ctx.SessionID(),
				"display":   display,
				"error":     err,
			}).Error("Failed to connect to local X11 server")
		}
		return nil, err
	}
	return x11Conn, nil
}

// logX11Established logs successful X11 forwarding connection establishment.
func (h *X11Handler) logX11Established(ctx ssh.Context) {
	if h.logger != nil {
		h.logger.WithFields(logrus.Fields{
			"user":      ctx.User(),
			"sessionID": ctx.SessionID(),
		}).Info("X11 forwarding connection established")
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

// connectToLocalX11 establishes a connection to the local X11 server backing
// the given session-allocated display number (see AllocateDisplay), rather
// than the sshd process's own $DISPLAY - which has no relation to any
// connecting client and is typically unset on a headless server.
func (h *X11Handler) connectToLocalX11(display int) (net.Conn, error) {
	// Connect to X11 server
	// Try Unix socket first (most common for local connections)
	socketPath := fmt.Sprintf("/tmp/.X11-unix/X%d", display)
	conn, err := net.Dial("unix", socketPath)
	if err == nil {
		return conn, nil
	}

	// Fall back to TCP connection if Unix socket fails
	host := "localhost"
	tcpAddr := net.JoinHostPort(host, strconv.Itoa(6000+display))
	conn, err = net.Dial("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to X11 server for display %d: %w", display, err)
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

	offset := h.getDisplayOffset()
	display := h.findAvailableDisplay(offset)
	h.displays[sessionID] = display

	return display, h.createCleanupFunc(sessionID)
}

// getDisplayOffset returns the X11 display offset from config or default.
func (h *X11Handler) getDisplayOffset() int {
	if h.config != nil && h.config.X11DisplayOffset > 0 {
		return h.config.X11DisplayOffset
	}
	return 10 // Default OpenSSH value
}

// findAvailableDisplay finds the first unused display number starting from offset.
func (h *X11Handler) findAvailableDisplay(offset int) int {
	display := offset
	for h.isDisplayInUse(display) {
		display++
	}
	return display
}

// isDisplayInUse checks if a display number is currently allocated.
func (h *X11Handler) isDisplayInUse(display int) bool {
	for _, d := range h.displays {
		if d == display {
			return true
		}
	}
	return false
}

// createCleanupFunc creates a function to release the allocated display.
func (h *X11Handler) createCleanupFunc(sessionID string) func() {
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.displays, sessionID)
	}
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
		return host, displayNum, screenNum, err
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
		return host, displayNum, screenNum, err
	}

	if colonIdx == 0 {
		// Unix socket format: :N
		displayNum, err = strconv.Atoi(parts[1:])
	} else {
		// TCP format: hostname:N
		host = parts[:colonIdx]
		displayNum, err = strconv.Atoi(parts[colonIdx+1:])
	}

	return host, displayNum, screenNum, err
}
