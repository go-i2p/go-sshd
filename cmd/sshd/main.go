// Package main provides the sshd-go server binary.
// This is a drop-in replacement for OpenSSH SSHD built using Go libraries.
//
// Shared CLI scaffolding, configuration loading, and host-key generation
// logic live in internal/cli - this file only supplies the TCP-specific
// listener creation that distinguishes this binary from cmd/garlicsshd.
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/go-i2p/go-sshd/internal/cli"
	"github.com/go-i2p/go-sshd/pkg/config"
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

// newRootCmd creates the root cobra command with OpenSSH-compatible flags.
func newRootCmd() *cobra.Command {
	return cli.NewRootCmd(cli.Options{
		Use:            "sshd",
		Version:        version,
		Commit:         commit,
		Date:           date,
		CreateListener: createTCPListener,
	})
}

// createTCPListener creates a TCP network listener on the configured port.
func createTCPListener(cfg *config.Config) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	return listener, nil
}

// generateHostKeys generates SSH host keys for the server.
// This is used by the systemd keygen service to generate keys on first install.
func generateHostKeys(cfg *config.Config) error {
	return cli.GenerateHostKeys(cfg)
}
