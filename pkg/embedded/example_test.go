package embedded_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/go-i2p/go-sshd/pkg/embedded"
	gossh "golang.org/x/crypto/ssh"
)

// ExampleNewStandardEmbeddedSSHServer demonstrates basic embedded SSH server usage.
func ExampleNewStandardEmbeddedSSHServer() {
	// Create a network listener on port 2222
	listener, err := net.Listen("tcp", "127.0.0.1:2222")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure server with defaults
	opts := embedded.DefaultConfigOptions()
	opts.Logging = &embedded.LoggingConfig{
		Level: "INFO",
	}

	// Create the embedded SSH server
	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		if err := server.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for server to initialize
	time.Sleep(100 * time.Millisecond)

	// Stop server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("Stop error: %v", err)
	}

	// Cleanup resources
	if err := server.Cleanup(); err != nil {
		log.Printf("Cleanup error: %v", err)
	}

	fmt.Println("Server lifecycle completed")
	// Output: Server lifecycle completed
}

// ExampleNewStandardEmbeddedSSHServer_customAuthentication demonstrates custom authentication.
func ExampleNewStandardEmbeddedSSHServer_customAuthentication() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure with custom authentication
	opts := embedded.DefaultConfigOptions()
	opts.Authentication = &embedded.AuthenticationConfig{
		PasswordAuth: true,
		CustomPasswordHandler: func(ctx context.Context, password string) error {
			// Custom authentication logic
			if password == "secret" {
				return nil
			}
			return fmt.Errorf("invalid password")
		},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR", // Reduce noise
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start and stop server
	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Custom authentication configured")
	// Output: Custom authentication configured
}

// ExampleNewStandardEmbeddedSSHServer_publicKeyAuth demonstrates public key authentication.
func ExampleNewStandardEmbeddedSSHServer_publicKeyAuth() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure public key authentication
	opts := embedded.DefaultConfigOptions()
	opts.Authentication = &embedded.AuthenticationConfig{
		PublicKeyAuth:       true,
		AuthorizedKeysFiles: []string{".ssh/authorized_keys"},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Public key authentication configured")
	// Output: Public key authentication configured
}

// ExampleNewStandardEmbeddedSSHServer_portForwarding demonstrates port forwarding configuration.
func ExampleNewStandardEmbeddedSSHServer_portForwarding() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Enable port forwarding
	opts := embedded.DefaultConfigOptions()
	opts.Forwarding = &embedded.ForwardingConfig{
		AllowTCPForwarding:   true,
		AllowAgentForwarding: true,
		AllowX11Forwarding:   false,
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Port forwarding enabled")
	// Output: Port forwarding enabled
}

// ExampleNewStandardEmbeddedSSHServer_sftpOnly demonstrates SFTP-only configuration.
func ExampleNewStandardEmbeddedSSHServer_sftpOnly() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure for SFTP only
	opts := embedded.DefaultConfigOptions()
	opts.Session = &embedded.SessionConfig{
		SFTPEnabled:     true,
		PermitRootLogin: "no",
		AllowUsers:      []string{"sftpuser"},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("SFTP-only server configured")
	// Output: SFTP-only server configured
}

// ExampleNewStandardEmbeddedSSHServer_customSession demonstrates custom session handling.
func ExampleNewStandardEmbeddedSSHServer_customSession() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure custom session handler
	opts := embedded.DefaultConfigOptions()
	opts.Session = &embedded.SessionConfig{
		CustomSessionHandler: func(sess embedded.Session) error {
			// Custom session logic
			log.Printf("Session started for user: %s", sess.User())
			return nil
		},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Custom session handler configured")
	// Output: Custom session handler configured
}

// ExampleNewStandardEmbeddedSSHServer_inMemoryHostKey demonstrates in-memory host key usage.
func ExampleNewStandardEmbeddedSSHServer_inMemoryHostKey() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// For demonstration, use auto-generated keys instead of embedding actual key data
	opts := embedded.DefaultConfigOptions()
	opts.HostKeys = embedded.HostKeyConfig{
		AutoGenerate:      true,
		AutoGenerateTypes: []string{"ed25519"},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("In-memory host key configured")
	// Output: In-memory host key configured
}

// ExampleNewStandardEmbeddedSSHServer_multipleAuth demonstrates multiple authentication methods.
func ExampleNewStandardEmbeddedSSHServer_multipleAuth() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Enable multiple authentication methods
	opts := embedded.DefaultConfigOptions()
	opts.Authentication = &embedded.AuthenticationConfig{
		PasswordAuth:            true,
		PublicKeyAuth:           true,
		KeyboardInteractiveAuth: true,
		PAMServiceName:          "sshd",
		AuthorizedKeysFiles:     []string{".ssh/authorized_keys"},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Multiple authentication methods configured")
	// Output: Multiple authentication methods configured
}

// ExampleConfigOptions_defaults demonstrates default configuration usage.
func ExampleConfigOptions_defaults() {
	opts := embedded.DefaultConfigOptions()

	fmt.Printf("Auto-generate keys: %v\n", opts.HostKeys.AutoGenerate)
	fmt.Printf("Public key auth: %v\n", opts.Authentication.PublicKeyAuth)
	fmt.Printf("SFTP enabled: %v\n", opts.Session.SFTPEnabled)
	fmt.Printf("Log level: %s\n", opts.Logging.Level)

	// Output:
	// Auto-generate keys: true
	// Public key auth: true
	// SFTP enabled: true
	// Log level: INFO
}

// ExampleEmbeddedSSHServer_lifecycle demonstrates complete server lifecycle.
func ExampleEmbeddedSSHServer_lifecycle() {
	// Phase 1: Create listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Phase 2: Configure server
	opts := embedded.DefaultConfigOptions()
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	// Phase 3: Create server
	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Phase 4: Start server
	go func() {
		if err := server.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for startup
	time.Sleep(50 * time.Millisecond)
	fmt.Println("Server started")

	// Phase 5: Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Printf("Stop error: %v", err)
	}
	fmt.Println("Server stopped")

	// Phase 6: Cleanup
	if err := server.Cleanup(); err != nil {
		log.Printf("Cleanup error: %v", err)
	}
	fmt.Println("Server cleaned up")

	// Output:
	// Server started
	// Server stopped
	// Server cleaned up
}

// ExampleStandardEmbeddedSSHServer_Configure demonstrates runtime configuration.
func ExampleStandardEmbeddedSSHServer_Configure() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Initial configuration
	opts := embedded.DefaultConfigOptions()
	opts.Logging = &embedded.LoggingConfig{
		Level: "INFO",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Update configuration before start
	newOpts := opts
	newOpts.Logging = &embedded.LoggingConfig{
		Level: "DEBUG",
	}

	if err := server.Configure(newOpts); err != nil {
		log.Printf("Configure error: %v", err)
	} else {
		fmt.Println("Configuration updated")
	}

	// Cleanup
	listener.Close()

	// Output: Configuration updated
}

// ExampleNewStandardEmbeddedSSHServer_certificateAuth demonstrates certificate authentication.
func ExampleNewStandardEmbeddedSSHServer_certificateAuth() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure certificate authentication
	opts := embedded.DefaultConfigOptions()
	opts.Authentication = &embedded.AuthenticationConfig{
		CertificateAuth:   true,
		TrustedUserCAKeys: []string{"/etc/ssh/ca.pub"},
		RevokedKeys:       []string{"/etc/ssh/revoked_keys"},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Certificate authentication configured")
	// Output: Certificate authentication configured
}

// ExampleNewStandardEmbeddedSSHServer_customPublicKeyValidator demonstrates custom key validation.
func ExampleNewStandardEmbeddedSSHServer_customPublicKeyValidator() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Configure custom public key validation
	opts := embedded.DefaultConfigOptions()
	opts.Authentication = &embedded.AuthenticationConfig{
		PublicKeyAuth: true,
		CustomPublicKeyHandler: func(ctx context.Context, key gossh.PublicKey) error {
			// Custom validation logic - check against database, API, etc.
			fingerprint := gossh.FingerprintSHA256(key)
			log.Printf("Validating key: %s", fingerprint)
			return nil // Accept all for demo
		},
	}
	opts.Logging = &embedded.LoggingConfig{
		Level: "ERROR",
	}

	server, err := embedded.NewStandardEmbeddedSSHServer(listener, opts)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = server.Stop(ctx)
	_ = server.Cleanup()

	fmt.Println("Custom public key validator configured")
	// Output: Custom public key validator configured
}
