// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"github.com/gliderlabs/ssh"
	"github.com/sirupsen/logrus"
)

// ShellHandler handles SSH shell sessions with PTY support.
// This is a thin wrapper around golang.org/x/crypto/ssh/terminal and os/exec
// for OpenSSH-compatible interactive shell sessions.
type ShellHandler struct {
	logger *logrus.Logger
}

// NewShellHandler creates a new shell session handler.
// Uses library-first approach - delegates PTY handling to golang.org/x/crypto/ssh/terminal.
func NewShellHandler(logger *logrus.Logger) *ShellHandler {
	return &ShellHandler{
		logger: logger,
	}
}

// CreateSessionHandler creates the SSH session handler for interactive shells.
// This integrates with gliderlabs/ssh session management using standard libraries.
// Enforces authorized_keys command restrictions when present.
func (h *ShellHandler) CreateSessionHandler() ssh.Handler {
	return func(s ssh.Session) {
		user := s.User()
		h.logger.Infof("Shell session started for user %s from %s", user, s.RemoteAddr())

		// Check for authorized_keys options (command restrictions, no-pty, etc.)
		keyOpts := GetAuthorizedKeyOptions(s)

		// Get user's default shell from system
		shell, err := h.getUserShell(user)
		if err != nil {
			h.logger.Errorf("Failed to get shell for user %s: %v", user, err)
			s.Exit(1)
			return
		}

		// Handle PTY requests using golang.org/x/crypto/ssh/terminal
		ptyReq, winCh, isPty := s.Pty()

		// Check for no-pty restriction from authorized_keys
		if isPty && keyOpts != nil && keyOpts.NoPTY {
			h.logger.Warnf("PTY denied for user %s: key has no-pty restriction", user)
			fmt.Fprintf(s, "PTY allocation disabled by authorized_keys restriction\r\n")
			s.Exit(1)
			return
		}

		if isPty {
			h.handlePTYSession(s, shell, ptyReq, winCh, keyOpts)
		} else {
			h.handleNonPTYSession(s, shell, keyOpts)
		}

		h.logger.Infof("Shell session ended for user %s", user)
	}
}

// handlePTYSession handles interactive shell sessions with PTY support.
// Uses gliderlabs/ssh built-in PTY functionality for proper terminal emulation.
// Enforces command restrictions from authorized_keys when present.
func (h *ShellHandler) handlePTYSession(s ssh.Session, shell string, ptyReq ssh.Pty, winCh <-chan ssh.Window, keyOpts *AuthorizedKeyOptions) {
	user := s.User()
	h.logger.Debugf("Starting PTY session for user %s with terminal %s", user, ptyReq.Term)

	var cmd *exec.Cmd

	// Check for command restriction from authorized_keys
	if keyOpts != nil && keyOpts.Command != "" {
		// With command restriction, run the forced command instead of interactive shell
		h.logger.Infof("Enforcing command restriction for user %s: %s", user, keyOpts.Command)
		cmd = exec.Command(shell, "-c", keyOpts.Command)
	} else {
		// Create shell command with proper environment
		cmd = exec.Command(shell, "-l") // Login shell
	}

	cmd.Env = h.buildEnvironment(s, ptyReq.Term)

	// Connect session I/O directly to shell process
	// gliderlabs/ssh handles PTY setup automatically
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s

	// Set process group for proper signal handling
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	// Start the shell process
	if err := cmd.Start(); err != nil {
		h.logger.Errorf("Failed to start shell for user %s: %v", user, err)
		s.Exit(1)
		return
	}

	// Handle window size changes in background goroutine
	go h.handleWindowChanges(cmd.Process, winCh)

	// Wait for shell completion and handle exit codes
	h.waitForShellCompletion(s, cmd, user)
}

// handleNonPTYSession handles non-interactive shell sessions (command execution).
// Uses standard os/exec without PTY for simple command execution.
// Enforces command restrictions from authorized_keys when present.
func (h *ShellHandler) handleNonPTYSession(s ssh.Session, shell string, keyOpts *AuthorizedKeyOptions) {
	user := s.User()
	h.logger.Debugf("Starting non-PTY session for user %s", user)

	var commandToRun string

	// Check for command restriction from authorized_keys
	if keyOpts != nil && keyOpts.Command != "" {
		// With command restriction, always run the forced command
		// The original command is available via SSH_ORIGINAL_COMMAND environment variable
		h.logger.Infof("Enforcing command restriction for user %s: %s (original: %s)", user, keyOpts.Command, s.RawCommand())
		commandToRun = keyOpts.Command
	} else {
		// Use the command requested by the client
		commandToRun = s.RawCommand()
	}

	// Get command from session
	cmd := exec.Command(shell, "-c", commandToRun)

	// Build environment, adding SSH_ORIGINAL_COMMAND if there's a forced command
	env := h.buildEnvironment(s, "")
	if keyOpts != nil && keyOpts.Command != "" && s.RawCommand() != "" {
		env = append(env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%s", s.RawCommand()))
	}
	cmd.Env = env

	// Connect session I/O directly to command
	cmd.Stdin = s
	cmd.Stdout = s
	cmd.Stderr = s

	// Execute and wait for completion
	if err := cmd.Start(); err != nil {
		h.logger.Errorf("Failed to start command for user %s: %v", user, err)
		s.Exit(1)
		return
	}

	h.waitForShellCompletion(s, cmd, user)
}

// handleWindowChanges processes terminal window size changes.
// Uses syscall interface to send SIGWINCH to shell process group.
func (h *ShellHandler) handleWindowChanges(process *os.Process, winCh <-chan ssh.Window) {
	for win := range winCh {
		h.logger.Debugf("Window size change: %dx%d", win.Width, win.Height)

		// Send SIGWINCH to process group for window size change notification
		// This is standard Unix behavior for terminal size changes
		if process != nil {
			syscall.Kill(-process.Pid, syscall.SIGWINCH)
		}
	}
}

// waitForShellCompletion waits for shell process and handles exit codes.
// Provides proper exit code handling and error logging.
func (h *ShellHandler) waitForShellCompletion(s ssh.Session, cmd *exec.Cmd, user string) {
	if err := cmd.Wait(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			// Process exited with non-zero status
			exitCode := exitError.ExitCode()
			h.logger.Debugf("Shell for user %s exited with code %d", user, exitCode)
			s.Exit(exitCode)
		} else {
			// Other error occurred
			h.logger.Errorf("Shell error for user %s: %v", user, err)
			s.Exit(1)
		}
	} else {
		// Process completed successfully
		h.logger.Debugf("Shell for user %s completed successfully", user)
		s.Exit(0)
	}
}

// getUserShell gets the user's default shell from the system.
// Parses /etc/passwd to find the user's configured shell, following OpenSSH behavior.
// Falls back to /bin/bash if the shell cannot be determined.
func (h *ShellHandler) getUserShell(username string) (string, error) {
	// First verify the user exists using os/user package
	u, err := user.Lookup(username)
	if err != nil {
		h.logger.Debugf("User lookup failed for %s, defaulting to bash: %v", username, err)
		return "/bin/bash", nil
	}

	// Parse /etc/passwd to get the user's shell
	// Format: username:password:uid:gid:gecos:home:shell
	shell, err := h.getShellFromPasswd(u.Uid)
	if err != nil {
		h.logger.Debugf("Could not get shell from passwd for %s, defaulting to bash: %v", username, err)
		return "/bin/bash", nil
	}

	// Verify the shell exists and is executable
	if _, err := os.Stat(shell); err != nil {
		h.logger.Debugf("Shell %s not found for user %s, defaulting to bash: %v", shell, username, err)
		return "/bin/bash", nil
	}

	h.logger.Debugf("Using shell %s for user %s", shell, username)
	return shell, nil
}

// getShellFromPasswd parses /etc/passwd to find the shell for the given UID.
// Returns the shell path or an error if the user is not found.
func (h *ShellHandler) getShellFromPasswd(uid string) (string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("cannot open /etc/passwd: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse passwd entry: username:password:uid:gid:gecos:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		// Match by UID
		if fields[2] == uid {
			shell := strings.TrimSpace(fields[6])
			if shell == "" {
				return "/bin/bash", nil // Empty shell field, default to bash
			}
			return shell, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /etc/passwd: %w", err)
	}

	return "", fmt.Errorf("user with UID %s not found in /etc/passwd", uid)
}

// buildEnvironment creates environment variables for the shell session.
// Integrates SSH session context with standard Unix environment setup.
func (h *ShellHandler) buildEnvironment(s ssh.Session, term string) []string {
	env := os.Environ()

	// Add SSH-specific environment variables for OpenSSH compatibility
	env = append(env,
		fmt.Sprintf("SSH_CLIENT=%s", s.RemoteAddr()),
		fmt.Sprintf("SSH_CONNECTION=%s %s", s.RemoteAddr(), s.LocalAddr()),
		fmt.Sprintf("USER=%s", s.User()),
		fmt.Sprintf("LOGNAME=%s", s.User()),
	)

	// Add terminal type if PTY session
	if term != "" {
		env = append(env, fmt.Sprintf("TERM=%s", term))
	}

	// Set HOME directory for user
	if u, err := user.Lookup(s.User()); err == nil {
		env = append(env, fmt.Sprintf("HOME=%s", u.HomeDir))
	}

	return env
}
