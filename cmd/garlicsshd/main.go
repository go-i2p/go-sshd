// Package main provides the sshd-go server binary.
// This is a drop-in replacement for OpenSSH SSHD built using Go libraries.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/crypto"
	"github.com/go-i2p/go-sshd/pkg/embedded"
	"github.com/go-i2p/go-sshd/pkg/server"
	"github.com/go-i2p/onramp"
	"github.com/spf13/cobra"
)

var (
	// Version information - will be set by build process
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newRootCmd creates the root cobra command with OpenSSH-compatible flags
func newRootCmd() *cobra.Command {
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
		Use:   "sshd",
		Short: "OpenSSH-compatible SSH daemon written in Go",
		Long: `sshd-go is a drop-in replacement for OpenSSH SSHD that provides
100% compatibility with OpenSSH clients while leveraging Go's deployment
advantages including single binary distribution and efficient resource usage.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("sshd-go %s (commit %s, built %s)\n", version, commit, date)
				return nil
			}

			// Load and apply configuration
			cfg, err := loadAndApplyConfig(configFile, port)
			if err != nil {
				return err
			}

			// Handle special modes
			if testConfig {
				return validateAndReportConfig(cfg)
			}
			if generateKeys {
				return generateHostKeys(cfg)
			}
			if inetdMode {
				return runInetdMode(cfg)
			}

			// Run standard server mode
			return runStandardServerMode(cfg)
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
	cmd.Flags().BoolVarP(daemon, "daemon", "D", false, "run in foreground mode")
	cmd.Flags().BoolVarP(testConfig, "test", "t", false, "test configuration and exit")
	cmd.Flags().BoolVarP(showVersion, "version", "V", false, "show version information")
	cmd.Flags().BoolVarP(inetdMode, "inetd", "i", false, "run from inetd/systemd socket activation")
	cmd.Flags().BoolVarP(generateKeys, "generate-keys", "G", false, "generate host keys and exit")
}

// runStandardServerMode initializes and runs the SSH server in standard mode.
func runStandardServerMode(cfg *config.Config) error {
	listener, err := createGarlicListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	srv, err := createEmbeddedServer(cfg, listener)
	if err != nil {
		return err
	}

	setupServerCleanup(srv)
	return srv.Start()
}

// createGarlicListener creates a garlic network listener for I2P connections.
func createGarlicListener() (net.Listener, error) {
	garlic, err := onramp.NewGarlic("garlicsshd", "127.0.0.1:7656", onramp.OPT_WIDE)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	listener, err := garlic.Listen()
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return listener, nil
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

// setupServerCleanup configures deferred cleanup operations for the server.
func setupServerCleanup(srv embedded.EmbeddedSSHServer) {
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if stopErr := srv.Stop(ctx); stopErr != nil {
			fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", stopErr)
		}
		srv.Cleanup()
	}()
}

// validateAndReportConfig performs comprehensive configuration validation
// and provides detailed reporting compatible with OpenSSH's config test mode.
func validateAndReportConfig(cfg *config.Config) error {
	// Perform comprehensive validation
	result := cfg.Validate()

	// Print detailed validation report
	printValidationHeader(result)
	printIssuesByLevel(result)
	printValidationSummary(result)

	// Exit with error code if configuration is invalid
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
	// Create server for inetd mode
	srv, err := server.NewInetd(cfg)
	if err != nil {
		return fmt.Errorf("failed to create inetd server: %w", err)
	}

	// Use stdin/stdout as the network connection (provided by systemd socket activation)
	conn := &stdinoutConn{}

	// Handle the single connection
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

// generateHostKeys generates SSH host keys for the server.
// This is used by the systemd keygen service to generate keys on first install.
func generateHostKeys(cfg *config.Config) error {
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
