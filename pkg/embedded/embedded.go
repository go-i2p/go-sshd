// Package embedded provides an embeddable SSH server interface for integrating
// go-sshd into other Go applications. This package maintains OpenSSH compatibility
// while allowing programmatic configuration.
package embedded

import (
	"context"
	"net"

	"github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
)

// EmbeddedSSHServer defines the interface for an embeddable SSH server.
// Implementations provide programmatic control over server lifecycle and configuration.
type EmbeddedSSHServer interface {
	// Configure applies configuration options to the server.
	// Must be called before Start(). Can be called multiple times to update configuration.
	Configure(opts ConfigOptions) error

	// Start begins accepting SSH connections on the provided listener.
	// Blocks until Stop() is called or an error occurs.
	Start() error

	// Stop initiates graceful shutdown with context timeout.
	// Waits for active connections to close or context deadline.
	Stop(ctx context.Context) error

	// Cleanup releases all server resources (host keys, file handles, etc.).
	// Should be called after Stop() completes.
	Cleanup() error
}

// ConfigOptions provides programmatic configuration for embedded SSH servers.
// Fields map to OpenSSH sshd_config directives where applicable.
type ConfigOptions struct {
	// Listener is the network listener for accepting SSH connections.
	// Required. Bypasses sshd_config Port/ListenAddress directives.
	Listener net.Listener

	// HostKeys specifies SSH host key configuration.
	// At least one host key is required for server operation.
	HostKeys HostKeyConfig

	// Authentication configures SSH authentication methods.
	// If nil, uses DefaultAuthenticationConfig().
	Authentication *AuthenticationConfig

	// Session configures session behavior and subsystems.
	// If nil, uses DefaultSessionConfig().
	Session *SessionConfig

	// Logging configures server logging behavior.
	// If nil, uses DefaultLoggingConfig().
	Logging *LoggingConfig

	// Forwarding configures port forwarding and agent forwarding.
	// If nil, uses DefaultForwardingConfig().
	Forwarding *ForwardingConfig

	// Metrics configures Prometheus metrics and health check endpoints.
	// If nil or Metrics.Enabled is false, no metrics server is started.
	Metrics *MetricsConfig
}

// HostKeyConfig specifies host key sources for the SSH server.
// Provide either file paths or in-memory key data.
type HostKeyConfig struct {
	// Paths to host key files (e.g., "/etc/ssh/ssh_host_rsa_key").
	// Keys are loaded from disk and validated.
	Paths []string

	// In-memory host key data (PEM-encoded private keys).
	// Used when file-based keys are not available.
	Data [][]byte

	// AutoGenerate enables automatic host key generation if no keys provided.
	// Generated keys are ephemeral (lost on server restart).
	AutoGenerate bool

	// AutoGenerateTypes specifies key types to generate when AutoGenerate is true.
	// Valid values: "rsa", "ecdsa", "ed25519"
	// Default: ["rsa", "ecdsa", "ed25519"]
	AutoGenerateTypes []string
}

// AuthenticationConfig specifies SSH authentication method configuration.
type AuthenticationConfig struct {
	// PasswordAuth enables password-based authentication via PAM.
	PasswordAuth bool

	// PAMServiceName specifies the PAM service name for authentication.
	// Default: "sshd"
	PAMServiceName string

	// PublicKeyAuth enables public key authentication.
	PublicKeyAuth bool

	// AuthorizedKeysFiles specifies paths to authorized_keys files.
	// Supports OpenSSH patterns: %h (home dir), %u (username)
	// Default: [".ssh/authorized_keys", ".ssh/authorized_keys2"]
	AuthorizedKeysFiles []string

	// KeyboardInteractiveAuth enables keyboard-interactive authentication (PAM).
	KeyboardInteractiveAuth bool

	// CertificateAuth enables SSH certificate-based authentication.
	CertificateAuth bool

	// TrustedUserCAKeys specifies paths to CA public keys for user certificates.
	TrustedUserCAKeys []string

	// RevokedKeys specifies paths to files containing revoked certificates/keys.
	RevokedKeys []string

	// CustomPublicKeyHandler provides custom public key validation logic.
	// If set, overrides default authorized_keys and certificate validation.
	CustomPublicKeyHandler func(ctx context.Context, key gossh.PublicKey) error

	// CustomPasswordHandler provides custom password validation logic.
	// If set, overrides default PAM authentication.
	CustomPasswordHandler func(ctx context.Context, password string) error
}

// SessionConfig specifies SSH session behavior and subsystems.
type SessionConfig struct {
	// ShellCommand specifies the shell to execute for interactive sessions.
	// Default: user's default shell from /etc/passwd
	ShellCommand string

	// SFTPEnabled enables the SFTP subsystem for file transfers.
	// Default: true
	SFTPEnabled bool

	// SFTPRootDir restricts SFTP access to a root directory (chroot-like).
	// Empty string allows full filesystem access (subject to OS permissions).
	SFTPRootDir string

	// PermitRootLogin controls root user SSH access.
	// Valid values: "yes", "no", "prohibit-password", "forced-commands-only"
	// Default: "prohibit-password"
	PermitRootLogin string

	// AllowUsers restricts access to specified usernames (OpenSSH patterns).
	// Empty list allows all users.
	AllowUsers []string

	// DenyUsers denies access to specified usernames (OpenSSH patterns).
	// Empty list denies no users.
	DenyUsers []string

	// CustomSessionHandler provides custom session handling logic.
	// If set, overrides default shell execution.
	CustomSessionHandler func(sess Session) error
}

// Session represents an active SSH session in custom handlers.
type Session interface {
	// User returns the authenticated username.
	User() string

	// RemoteAddr returns the client's network address.
	RemoteAddr() net.Addr

	// Command returns the command to execute (empty for shell sessions).
	Command() []string

	// Pty returns PTY details if requested, or nil.
	Pty() *PtyRequest

	// Environ returns environment variables.
	Environ() []string
}

// PtyRequest represents a PTY allocation request.
type PtyRequest struct {
	Term   string
	Width  int
	Height int
}

// LoggingConfig specifies server logging behavior.
type LoggingConfig struct {
	// Level sets the logging verbosity.
	// Valid values: "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG"
	// Default: "INFO"
	Level string

	// Logger provides a custom logrus logger instance.
	// If nil, a new logger is created with the specified Level.
	Logger *logrus.Logger

	// SyslogFacility specifies syslog facility for system logging.
	// Valid values: "DAEMON", "USER", "AUTH", "LOCAL0" through "LOCAL7"
	// Default: "AUTH"
	SyslogFacility string

	// LogFile specifies a file path for logging output.
	// If empty, logs to stderr.
	LogFile string
}

// ForwardingConfig specifies port forwarding and agent forwarding behavior.
type ForwardingConfig struct {
	// AllowTCPForwarding enables local and remote port forwarding.
	// Default: false
	AllowTCPForwarding bool

	// AllowAgentForwarding enables SSH agent forwarding.
	// Default: false
	AllowAgentForwarding bool

	// AllowX11Forwarding enables X11 display forwarding.
	// Default: false
	AllowX11Forwarding bool

	// X11DisplayOffset specifies the first display number for X11 forwarding.
	// Default: 10
	X11DisplayOffset int

	// X11UseLocalhost forces X11 forwarding to bind to localhost only.
	// Default: true
	X11UseLocalhost bool

	// GatewayPorts allows remote port forwarding to bind to non-localhost addresses.
	// Default: false
	GatewayPorts bool
}

// MetricsConfig specifies Prometheus metrics and health check configuration.
type MetricsConfig struct {
	// Enabled controls whether to start the metrics server.
	// Default: false
	Enabled bool

	// Address specifies the HTTP address to bind metrics server to (e.g., "127.0.0.1:9100").
	// If empty, defaults to "127.0.0.1:9100".
	// Default: "127.0.0.1:9100"
	Address string
}

// DefaultConfigOptions returns ConfigOptions with sensible defaults.
// Listener must be provided by caller before use.
func DefaultConfigOptions() ConfigOptions {
	return ConfigOptions{
		HostKeys: HostKeyConfig{
			AutoGenerate:      true,
			AutoGenerateTypes: []string{"rsa", "ecdsa", "ed25519"},
		},
		Authentication: DefaultAuthenticationConfig(),
		Session:        DefaultSessionConfig(),
		Logging:        DefaultLoggingConfig(),
		Forwarding:     DefaultForwardingConfig(),
		Metrics:        DefaultMetricsConfig(),
	}
}

// DefaultAuthenticationConfig returns authentication config with sensible defaults.
func DefaultAuthenticationConfig() *AuthenticationConfig {
	return &AuthenticationConfig{
		PasswordAuth:            false, // Disabled by default for security
		PAMServiceName:          "sshd",
		PublicKeyAuth:           true,
		AuthorizedKeysFiles:     []string{".ssh/authorized_keys", ".ssh/authorized_keys2"},
		KeyboardInteractiveAuth: false,
		CertificateAuth:         false,
	}
}

// DefaultSessionConfig returns session config with sensible defaults.
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		ShellCommand:    "", // Use system default
		SFTPEnabled:     true,
		SFTPRootDir:     "",
		PermitRootLogin: "prohibit-password",
		AllowUsers:      []string{},
		DenyUsers:       []string{},
	}
}

// DefaultLoggingConfig returns logging config with sensible defaults.
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Level:          "INFO",
		Logger:         nil,
		SyslogFacility: "AUTH",
		LogFile:        "",
	}
}

// DefaultForwardingConfig returns forwarding config with sensible defaults.
func DefaultForwardingConfig() *ForwardingConfig {
	return &ForwardingConfig{
		AllowTCPForwarding:   false,
		AllowAgentForwarding: false,
		AllowX11Forwarding:   false,
		X11DisplayOffset:     10,
		X11UseLocalhost:      true,
		GatewayPorts:         false,
	}
}

// DefaultMetricsConfig returns metrics config with sensible defaults.
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled: false,
		Address: "127.0.0.1:9100",
	}
}
