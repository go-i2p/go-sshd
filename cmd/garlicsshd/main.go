// Package main provides the garlicsshd server binary.
// This is an I2P/onramp-based variant of sshd-go, providing the same
// OpenSSH-compatible daemon over I2P garlic routing instead of plain TCP.
//
// Shared CLI scaffolding, configuration loading, and host-key generation
// logic live in internal/cli - this file only supplies the garlic-specific
// listener creation that distinguishes this binary from cmd/sshd.
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/go-i2p/go-sshd/internal/cli"
	"github.com/go-i2p/go-sshd/pkg/config"
	"github.com/go-i2p/onramp"
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
		CreateListener: createGarlicListener,
	})
}

// createGarlicListener creates a garlic network listener for I2P connections.
func createGarlicListener(cfg *config.Config) (net.Listener, error) {
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

// generateHostKeys generates SSH host keys for the server.
// This is used by the systemd keygen service to generate keys on first install.
func generateHostKeys(cfg *config.Config) error {
	return cli.GenerateHostKeys(cfg)
}
