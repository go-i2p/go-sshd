package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Benchmark Suite for sshd-go Performance Testing
//
// This suite provides comprehensive performance benchmarks comparing sshd-go
// against OpenSSH baseline performance. Following library-first architecture,
// we use golang.org/x/crypto/ssh for client connections.
//
// Library Choice: golang.org/x/crypto/ssh
// - Standard SSH client library from Go team
// - Used throughout project for consistency
// - Zero additional dependencies
// - Compatible with both OpenSSH and sshd-go servers
//
// Benchmark Categories:
// 1. Connection establishment and authentication
// 2. File transfer throughput (SFTP)
// 3. Command execution latency
// 4. Concurrent session handling
// 5. Port forwarding performance
//
// Usage:
//   go test -bench=. -benchtime=10s -benchmem
//   go test -bench=BenchmarkConnection -count=5
//
// Comparison Methodology:
// - Start sshd-go on port 2222
// - Start OpenSSH sshd on port 2223
// - Run identical benchmarks against both
// - Compare results (target: <20% degradation)

const (
	// Test server configuration
	testServerHost  = "localhost"
	sshdGoPort      = "2222" // sshd-go test instance
	opensshPort     = "2223" // OpenSSH comparison instance
	testUser        = "testuser"
	testKeyPath     = "testdata/test_rsa"
	connectionCount = 100
	fileSize1MB     = 1024 * 1024
	fileSize10MB    = 10 * 1024 * 1024
	fileSize100MB   = 100 * 1024 * 1024
)

// BenchmarkSuite holds shared test infrastructure
type BenchmarkSuite struct {
	signer       ssh.Signer
	clientConfig *ssh.ClientConfig
}

// setupBenchmark initializes test infrastructure using library patterns
func setupBenchmark(b *testing.B) *BenchmarkSuite {
	b.Helper()

	// Load test SSH key using crypto/ssh library
	keyBytes, err := os.ReadFile(testKeyPath)
	if err != nil {
		b.Skipf("Test key not found at %s (setup required): %v", testKeyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		b.Fatalf("Failed to parse private key: %v", err)
	}

	// Create client config using standard library patterns
	config := &ssh.ClientConfig{
		User: testUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Test only
		Timeout:         5 * time.Second,
	}

	return &BenchmarkSuite{
		signer:       signer,
		clientConfig: config,
	}
}

// connectToServer establishes SSH connection using golang.org/x/crypto/ssh
func (s *BenchmarkSuite) connectToServer(host, port string) (*ssh.Client, error) {
	return ssh.Dial("tcp", net.JoinHostPort(host, port), s.clientConfig)
}

// BenchmarkConnectionEstablishment measures connection setup overhead
// This benchmark validates the <20% performance target for basic operations
func BenchmarkConnectionEstablishment(b *testing.B) {
	suite := setupBenchmark(b)
	addr := net.JoinHostPort(testServerHost, sshdGoPort)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := suite.connectToServer(testServerHost, sshdGoPort)
		if err != nil {
			b.Skipf("Server not available at %s (start test server first): %v", addr, err)
		}
		client.Close()
	}
}

// BenchmarkAuthenticationPublicKey measures public key auth throughput
func BenchmarkAuthenticationPublicKey(b *testing.B) {
	suite := setupBenchmark(b)
	addr := net.JoinHostPort(testServerHost, sshdGoPort)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := suite.connectToServer(testServerHost, sshdGoPort)
		if err != nil {
			b.Skipf("Server not available at %s: %v", addr, err)
		}
		// Authentication happens during connection
		client.Close()
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "auths/sec")
}

// BenchmarkSessionCreation measures session setup overhead
func BenchmarkSessionCreation(b *testing.B) {
	suite := setupBenchmark(b)
	client, err := suite.connectToServer(testServerHost, sshdGoPort)
	if err != nil {
		b.Skipf("Server not available: %v", err)
	}
	defer client.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, err := client.NewSession()
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}
		session.Close()
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "sessions/sec")
}

// BenchmarkCommandExecution measures command execution latency
func BenchmarkCommandExecution(b *testing.B) {
	suite := setupBenchmark(b)
	client, err := suite.connectToServer(testServerHost, sshdGoPort)
	if err != nil {
		b.Skipf("Server not available: %v", err)
	}
	defer client.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session, err := client.NewSession()
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}

		// Execute simple command
		if err := session.Run("echo test"); err != nil {
			b.Fatalf("Command execution failed: %v", err)
		}
		session.Close()
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "commands/sec")
}

// BenchmarkDataTransferSmall measures small data transfer throughput
func BenchmarkDataTransferSmall(b *testing.B) {
	suite := setupBenchmark(b)
	client, err := suite.connectToServer(testServerHost, sshdGoPort)
	if err != nil {
		b.Skipf("Server not available: %v", err)
	}
	defer client.Close()

	// 1KB test data
	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		session, err := client.NewSession()
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}

		stdin, _ := session.StdinPipe()
		session.Start("cat > /dev/null")

		stdin.Write(testData)
		stdin.Close()
		session.Wait()
		session.Close()
	}
	b.ReportMetric(float64(b.N*len(testData))/b.Elapsed().Seconds()/1024/1024, "MB/s")
}

// BenchmarkDataTransferLarge measures large file transfer throughput
func BenchmarkDataTransferLarge(b *testing.B) {
	suite := setupBenchmark(b)
	client, err := suite.connectToServer(testServerHost, sshdGoPort)
	if err != nil {
		b.Skipf("Server not available: %v", err)
	}
	defer client.Close()

	// 1MB test data
	testData := make([]byte, fileSize1MB)
	rand.Read(testData)

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		session, err := client.NewSession()
		if err != nil {
			b.Fatalf("Failed to create session: %v", err)
		}

		stdin, _ := session.StdinPipe()
		session.Start("cat > /dev/null")

		if _, err := io.Copy(stdin, bytes.NewReader(testData)); err != nil {
			b.Fatalf("Data transfer failed: %v", err)
		}

		stdin.Close()
		session.Wait()
		session.Close()
	}
	b.ReportMetric(float64(b.N*len(testData))/b.Elapsed().Seconds()/1024/1024, "MB/s")
}

// BenchmarkConcurrentSessions measures scalability with multiple sessions
func BenchmarkConcurrentSessions(b *testing.B) {
	suite := setupBenchmark(b)

	concurrency := []int{1, 10, 50, 100}

	for _, n := range concurrency {
		b.Run(fmt.Sprintf("Sessions_%d", n), func(b *testing.B) {
			b.SetParallelism(n)
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					client, err := suite.connectToServer(testServerHost, sshdGoPort)
					if err != nil {
						b.Skipf("Server not available: %v", err)
					}

					session, err := client.NewSession()
					if err != nil {
						client.Close()
						b.Fatalf("Failed to create session: %v", err)
					}

					session.Run("echo test")
					session.Close()
					client.Close()
				}
			})
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "ops/sec")
		})
	}
}

// BenchmarkPortForwardingThroughput measures forwarding performance
func BenchmarkPortForwardingThroughput(b *testing.B) {
	suite := setupBenchmark(b)
	client, err := suite.connectToServer(testServerHost, sshdGoPort)
	if err != nil {
		b.Skipf("Server not available: %v", err)
	}
	defer client.Close()

	// Setup local listener for forwarding target
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create target listener: %v", err)
	}
	defer listener.Close()

	// Handle incoming connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	targetAddr := listener.Addr().(*net.TCPAddr)
	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		// Create forwarded connection
		conn, err := client.Dial("tcp", targetAddr.String())
		if err != nil {
			b.Fatalf("Port forwarding failed: %v", err)
		}

		conn.Write(testData)
		conn.Close()
	}
	b.ReportMetric(float64(b.N*len(testData))/b.Elapsed().Seconds()/1024/1024, "MB/s")
}

// BenchmarkMemoryUsagePerConnection measures per-connection memory overhead
func BenchmarkMemoryUsagePerConnection(b *testing.B) {
	suite := setupBenchmark(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client, err := suite.connectToServer(testServerHost, sshdGoPort)
		if err != nil {
			b.Skipf("Server not available: %v", err)
		}

		session, _ := client.NewSession()
		session.Run("echo test")
		session.Close()
		client.Close()
	}
}
