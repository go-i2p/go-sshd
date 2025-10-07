// Package main provides the sshd-go server binary.
// This is a drop-in replacement for OpenSSH SSHD built using Go libraries.
package main

import (
	"fmt"
	"os"

	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/go-sshd/pkg/server"
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
		configFile  string
		port        int
		daemon      bool
		testConfig  bool
		showVersion bool
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

			// Load configuration using OpenSSH-compatible parser
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Override port if specified on command line
			if port != 0 {
				cfg.Port = port
			}

			// Test configuration and exit if requested
			if testConfig {
				fmt.Println("Configuration file is valid")
				return nil
			}

			// Create and start the SSH server with config file for reload capability
			srv, err := server.NewWithConfigFile(cfg, configFile)
			if err != nil {
				return fmt.Errorf("failed to create server: %w", err)
			}

			// Ensure server is properly stopped on exit
			defer func() {
				if stopErr := srv.Stop(); stopErr != nil {
					fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", stopErr)
				}
			}()

			// Start server in daemon mode or foreground
			if daemon {
				return srv.StartDaemon()
			}
			return srv.Start()
		},
	}

	// OpenSSH-compatible command line flags
	cmd.Flags().StringVarP(&configFile, "config", "f", "/etc/ssh/sshd_config", "configuration file")
	cmd.Flags().IntVarP(&port, "port", "p", 0, "port number (overrides config)")
	cmd.Flags().BoolVarP(&daemon, "daemon", "D", false, "run in foreground mode")
	cmd.Flags().BoolVarP(&testConfig, "test", "t", false, "test configuration and exit")
	cmd.Flags().BoolVarP(&showVersion, "version", "V", false, "show version information")

	return cmd
}
