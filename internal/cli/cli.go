// Package cli provides the shared cobra command scaffolding, configuration
// loading, and host-key generation logic used by both the cmd/sshd and
// cmd/garlicsshd binaries. The two binaries are otherwise identical except
// for how they create their network listener (TCP vs I2P garlic routing),
// which is supplied via ListenerFactory.
package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/crypto"
	"github.com/go-i2p/go-sshd/pkg/embedded"
	"github.com/go-i2p/go-sshd/pkg/server"
	"github.com/go-i2p/go-sshd/pkg/signals"
)

// ListenerFactory creates the network listener a server binary accepts
// connections on. Implementations differ per transport (plain TCP for
// cmd/sshd, I2P garlic routing for cmd/garlicsshd).
type ListenerFactory func(cfg *config.Config) (net.Listener, error)

// Options configures the shared root command for a specific binary.
type Options struct {
	// Use is the cobra command name (e.g. "sshd").
	Use string
	// Version, Commit, and Date are reported by the --version flag.
	Version, Commit, Date string
	// CreateListener creates the listener used in standard server mode.
	CreateListener ListenerFactory
}

// NewRootCmd creates the root cobra command with OpenSSH-compatible flags,
// shared by all sshd-go binaries.
func NewRootCmd(opts Options) *cobra.Command {
	var (
		configFile   string
		port         int
		daemon       bool
		testConfig   bool
		showVersion  bool
		inetdMode    bool
		generateKeys bool
	)

	cmd := &cobra.Command{
		Use:   opts.Use,
		Short: "OpenSSH-compatible SSH daemon written in Go",
		Long: `sshd-go is a drop-in replacement for OpenSSH SSHD that provides
100% compatibility with OpenSSH clients while leveraging Go's deployment
advantages including single binary distribution and efficient resource usage.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("sshd-go %s (commit %s, built %s)\n", opts.Version, opts.Commit, opts.Date)
				return nil
			}

			cfg, err := loadAndApplyConfig(configFile, port)
			if err != nil {
				return err
			}

			if testConfig {
				return validateAndReportConfig(cfg)
			}
			if generateKeys {
				return GenerateHostKeys(cfg)
			}
			if inetdMode {
				return runInetdMode(cfg)
			}

			return runStandardServerMode(configFile, cfg, opts.CreateListener)
		},
	}

	configureCommandFlags(cmd, &configFile, &port, &daemon, &testConfig, &showVersion, &inetdMode, &generateKeys)
	return cmd
}

// loadAndApplyConfig loads the SSH configuration file and applies command-line overrides.
func loadAndApplyConfig(configFile string, port int) (*config.Config, error) {
	cfg, err := config.Load(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	if port != 0 {
		cfg.Port = port
	}

	return cfg, nil
}

// configureCommandFlags sets up all OpenSSH-compatible command line flags.
func configureCommandFlags(cmd *cobra.Command, configFile *string, port *int, daemon *bool,
	testConfig, showVersion, inetdMode, generateKeys *bool,
) {
	cmd.Flags().StringVarP(configFile, "config", "f", "/etc/ssh/sshd_config", "configuration file")
	cmd.Flags().IntVarP(port, "port", "p", 0, "port number (overrides config)")
	// Note: -D flag accepted for OpenSSH compatibility but has no effect.
	// Modern Go servers run in foreground by design for systemd/container management.
	cmd.Flags().BoolVarP(daemon, "daemon", "D", false, "run in foreground mode (default, for systemd/container compatibility)")
	cmd.Flags().BoolVarP(testConfig, "test", "t", false, "test configuration and exit")
	cmd.Flags().BoolVarP(showVersion, "version", "V", false, "show version information")
	cmd.Flags().BoolVarP(inetdMode, "inetd", "i", false, "run from inetd/systemd socket activation")
	cmd.Flags().BoolVarP(generateKeys, "generate-keys", "G", false, "generate host keys and exit")
}

// runStandardServerMode initializes and runs the SSH server in standard mode
// with proper signal handling for graceful shutdown (SIGTERM/SIGINT) and
// configuration reload (SIGHUP).
func runStandardServerMode(configFile string, cfg *config.Config, createListener ListenerFactory) error {
	listener, err := createListener(cfg)
	if err != nil {
		return err
	}
	defer listener.Close()

	srv, err := createEmbeddedServer(cfg, listener)
	if err != nil {
		return err
	}

	// Create a signal handler for graceful shutdown and configuration reload.
	handler := signals.NewHandler()
	defer handler.Stop()

	// Channels for signal events and server completion.
	serverErr := make(chan error, 1)
	reloadRequested := make(chan struct{}, 1)

	// Start the SSH server in a goroutine so we can monitor signals.
	go func() {
		serverErr <- srv.Start()
	}()

	// Monitor for reload signals in a separate goroutine.
	go func() {
		for {
			if handler.WaitForReload() == nil {
				return // Context cancelled, handler shutdown
			}
			select {
			case reloadRequested <- struct{}{}:
			default:
			}
		}
	}()

	// Main signal handling loop: monitor for shutdown and reload signals.
	for {
		select {
		case err := <-serverErr:
			// Server exited (normally or with error).
			return err

		case <-handler.Context().Done():
			// Shutdown signal received; gracefully stop the server.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Stop(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "error stopping server: %v\n", err)
			}
			srv.Cleanup()
			return nil

		case <-reloadRequested:
			// Reload signal (SIGHUP) received; reload configuration.
			newCfg, err := config.Load(configFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reloading configuration: %v\n", err)
				continue
			}

			// Reconfigure the embedded server with the new configuration.
			opts := configToEmbeddedOptions(newCfg)
			opts.Listener = listener
			if err := srv.Configure(opts); err != nil {
				fmt.Fprintf(os.Stderr, "error reconfiguring server: %v\n", err)
				continue
			}

			// Update the config reference so subsequent reloads use the right file.
			cfg = newCfg
		}
	}
}

// createEmbeddedServer creates and configures an embedded SSH server instance.
func createEmbeddedServer(cfg *config.Config, listener net.Listener) (embedded.EmbeddedSSHServer, error) {
	opts := configToEmbeddedOptions(cfg)
	opts.Listener = listener

	srv, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	return srv, nil
}

// validateAndReportConfig performs comprehensive configuration validation
// and provides detailed reporting compatible with OpenSSH's config test mode.
func validateAndReportConfig(cfg *config.Config) error {
	result := cfg.Validate()

	printValidationHeader(result)
	printIssuesByLevel(result)
	printValidationSummary(result)

	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

// printValidationHeader prints the validation status header.
func printValidationHeader(result *config.ValidationResult) {
	if result.Valid {
		fmt.Println("Configuration file is valid")
	} else {
		fmt.Printf("Configuration validation failed with %d error(s)\n", result.ErrorCount)
	}
}

// printIssuesByLevel prints all validation issues grouped by severity level.
func printIssuesByLevel(result *config.ValidationResult) {
	printErrorIssues(result)
	printWarningIssues(result)
	printInfoIssues(result)
}

// printErrorIssues prints all error-level validation issues.
func printErrorIssues(result *config.ValidationResult) {
	if result.ErrorCount > 0 {
		fmt.Printf("\nERRORS (%d):\n", result.ErrorCount)
		for _, issue := range result.Issues {
			if issue.Level == config.ValidationError {
				printIssue(issue)
			}
		}
	}
}

// printWarningIssues prints all warning-level validation issues.
func printWarningIssues(result *config.ValidationResult) {
	if result.WarnCount > 0 {
		fmt.Printf("\nWARNINGS (%d):\n", result.WarnCount)
		for _, issue := range result.Issues {
			if issue.Level == config.ValidationWarning {
				printIssue(issue)
			}
		}
	}
}

// printInfoIssues prints all informational validation issues.
func printInfoIssues(result *config.ValidationResult) {
	if result.InfoCount > 0 {
		fmt.Printf("\nINFORMATION (%d):\n", result.InfoCount)
		for _, issue := range result.Issues {
			if issue.Level == config.ValidationInfo {
				printIssue(issue)
			}
		}
	}
}

// printIssue formats and prints a single validation issue.
func printIssue(issue config.ValidationIssue) {
	fmt.Printf("  [%s] %s", issue.Directive, issue.Message)
	if issue.Suggestion != "" {
		fmt.Printf(" - %s", issue.Suggestion)
	}
	fmt.Println()
}

// printValidationSummary prints the final validation summary.
func printValidationSummary(result *config.ValidationResult) {
	if result.ErrorCount > 0 || result.WarnCount > 0 || result.InfoCount > 0 {
		fmt.Printf("\nValidation Summary: %d error(s), %d warning(s), %d info message(s)\n",
			result.ErrorCount, result.WarnCount, result.InfoCount)
	}
}

// runInetdMode runs the SSH server in inetd/socket activation mode.
// In this mode, the server handles a single connection passed via stdin/stdout
// and exits when the connection is closed. This is used for systemd socket activation.
func runInetdMode(cfg *config.Config) error {
	srv, err := server.NewInetd(cfg)
	if err != nil {
		return fmt.Errorf("failed to create inetd server: %w", err)
	}

	// Use stdin/stdout as the network connection (provided by systemd socket activation)
	conn := &stdinoutConn{}

	return srv.HandleConnection(conn)
}

// stdinoutConn implements net.Conn interface using stdin/stdout.
// This allows the SSH server to work with systemd socket activation.
type stdinoutConn struct{}

func (c *stdinoutConn) Read(b []byte) (n int, err error) {
	return os.Stdin.Read(b)
}

func (c *stdinoutConn) Write(b []byte) (n int, err error) {
	return os.Stdout.Write(b)
}

func (c *stdinoutConn) Close() error {
	// Don't actually close stdin/stdout as they're owned by the system
	return nil
}

func (c *stdinoutConn) LocalAddr() net.Addr {
	return &net.UnixAddr{Name: "stdin", Net: "unix"}
}

func (c *stdinoutConn) RemoteAddr() net.Addr {
	return &net.UnixAddr{Name: "stdout", Net: "unix"}
}

func (c *stdinoutConn) SetDeadline(t time.Time) error {
	// stdin/stdout don't support deadlines
	return nil
}

func (c *stdinoutConn) SetReadDeadline(t time.Time) error {
	// stdin/stdout don't support deadlines
	return nil
}

func (c *stdinoutConn) SetWriteDeadline(t time.Time) error {
	// stdin/stdout don't support deadlines
	return nil
}

// configToEmbeddedOptions converts a config.Config to embedded.ConfigOptions.
// This function maps OpenSSH configuration directives to the embedded server API.
func configToEmbeddedOptions(cfg *config.Config) embedded.ConfigOptions {
	return embedded.ConfigOptions{
		HostKeys: embedded.HostKeyConfig{
			Paths:        cfg.HostKey,
			AutoGenerate: len(cfg.HostKey) == 0, // Auto-generate if no keys specified
		},
		Authentication: &embedded.AuthenticationConfig{
			PasswordAuth:            cfg.PasswordAuthentication,
			PAMServiceName:          "sshd",
			PublicKeyAuth:           cfg.PubkeyAuthentication,
			AuthorizedKeysFiles:     cfg.AuthorizedKeysFile,
			KeyboardInteractiveAuth: cfg.KbdInteractiveAuthentication,
			CertificateAuth:         len(cfg.TrustedUserCAKeys) > 0,
			TrustedUserCAKeys:       cfg.TrustedUserCAKeys,
			RevokedKeys:             cfg.RevokedKeys,
		},
		Session: &embedded.SessionConfig{
			SFTPEnabled:     cfg.Subsystem["sftp"] != "",
			PermitRootLogin: cfg.PermitRootLogin,
			AllowUsers:      cfg.AllowUsers,
			DenyUsers:       cfg.DenyUsers,
		},
		Logging: &embedded.LoggingConfig{
			Level:          cfg.LogLevel,
			SyslogFacility: cfg.SyslogFacility,
			LogFile:        cfg.LogFile,
		},
		Forwarding: &embedded.ForwardingConfig{
			AllowTCPForwarding:   cfg.AllowTcpForwarding,
			AllowAgentForwarding: cfg.AllowAgentForwarding,
			AllowX11Forwarding:   cfg.X11Forwarding,
			X11DisplayOffset:     cfg.X11DisplayOffset,
			X11UseLocalhost:      cfg.X11UseLocalhost,
			GatewayPorts:         cfg.GatewayPorts,
		},
	}
}

// GenerateHostKeys generates SSH host keys for the server.
// This is used by the systemd keygen service to generate keys on first install.
func GenerateHostKeys(cfg *config.Config) error {
	// Use configured host keys or fall back to defaults
	keyPaths := cfg.HostKey
	if len(keyPaths) == 0 {
		keyPaths = []string{
			"/etc/ssh/ssh_host_rsa_key",
			"/etc/ssh/ssh_host_ecdsa_key",
			"/etc/ssh/ssh_host_ed25519_key",
		}
	}

	manager := crypto.NewHostKeyManager(keyPaths)

	// Generate all configured host keys
	_, err := manager.LoadOrGenerateKeys()
	if err != nil {
		return fmt.Errorf("failed to generate host keys: %w", err)
	}

	fmt.Printf("Host keys generated successfully:\n")
	for _, keyPath := range keyPaths {
		if keyPath != "" {
			fmt.Printf("  - %s\n", keyPath)
		}
	}

	return nil
}
