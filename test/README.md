# Performance Benchmarks

This directory contains comprehensive performance benchmarks for sshd-go, comparing it against OpenSSH baseline performance.

## Goal

Validate that sshd-go maintains performance within **20% of OpenSSH** across all operations, as specified in the project requirements.

## Architecture

Following the project's library-first philosophy:

- **Library**: `golang.org/x/crypto/ssh` (standard Go SSH client)
- **No custom protocol implementation**: All benchmarks use standard library
- **Identical test methodology**: Same client code tests both sshd-go and OpenSSH
- **Reproducible results**: Benchmarks use Go's built-in `testing.B` framework

## Benchmark Categories

### 1. Connection & Authentication
- `BenchmarkConnectionEstablishment`: SSH connection setup overhead
- `BenchmarkAuthenticationPublicKey`: Public key authentication throughput
- `BenchmarkSessionCreation`: Session establishment performance

### 2. Command Execution
- `BenchmarkCommandExecution`: Command execution latency
- Measures end-to-end time for simple command execution

### 3. Data Transfer
- `BenchmarkDataTransferSmall`: Small payload transfer (1KB)
- `BenchmarkDataTransferLarge`: Large file transfer (1MB)
- Validates throughput for file operations

### 4. Scalability
- `BenchmarkConcurrentSessions`: Multi-session handling (1, 10, 50, 100 sessions)
- `BenchmarkPortForwardingThroughput`: Port forwarding performance
- `BenchmarkMemoryUsagePerConnection`: Memory overhead analysis

## Setup

### Prerequisites

1. **Test SSH Key**: Generate test key pair
   ```bash
   mkdir -p test/testdata
   ssh-keygen -t rsa -b 2048 -f test/testdata/test_rsa -N ""
   ```

2. **Test User**: Create test user (requires root)
   ```bash
   sudo useradd -m -s /bin/bash testuser
   sudo mkdir -p /home/testuser/.ssh
   sudo cp test/testdata/test_rsa.pub /home/testuser/.ssh/authorized_keys
   sudo chown -R testuser:testuser /home/testuser/.ssh
   sudo chmod 700 /home/testuser/.ssh
   sudo chmod 600 /home/testuser/.ssh/authorized_keys
   ```

3. **Start sshd-go Test Server**:
   ```bash
   # Build the server
   go build -o sshd cmd/sshd/main.go
   
   # Start on port 2222
   sudo ./sshd -D -p 2222 -f test_sshd_config
   ```

4. **Start OpenSSH Reference Server** (optional, for comparison):
   ```bash
   # Create OpenSSH test config
   cat > /tmp/sshd_openssh_test.conf <<EOF
   Port 2223
   HostKey /etc/ssh/ssh_host_rsa_key
   PubkeyAuthentication yes
   PasswordAuthentication no
   Subsystem sftp /usr/lib/openssh/sftp-server
   EOF
   
   # Start OpenSSH on port 2223
   sudo /usr/sbin/sshd -D -f /tmp/sshd_openssh_test.conf
   ```

## Running Benchmarks

### Quick Run (sshd-go only)
```bash
cd test
go test -bench=. -benchtime=3s
```

### Detailed Analysis
```bash
# Run with memory profiling
go test -bench=. -benchtime=10s -benchmem

# Run specific benchmark
go test -bench=BenchmarkConnection -count=5

# Generate CPU profile
go test -bench=BenchmarkDataTransferLarge -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

### Comparative Testing
```bash
# Test sshd-go (port 2222)
go test -bench=. -benchtime=5s > results_sshdgo.txt

# Test OpenSSH (port 2223) - modify benchmark constants first
# Change sshdGoPort to "2223" in benchmark_test.go
go test -bench=. -benchtime=5s > results_openssh.txt

# Compare results
benchstat results_openssh.txt results_sshdgo.txt
```

## Interpreting Results

### Success Criteria
- **Connection Rate**: Within 20% of OpenSSH
- **Throughput**: File transfer speeds within 20% of OpenSSH
- **Latency**: Command execution within 20% of OpenSSH
- **Memory**: Per-connection memory usage <5MB
- **Concurrency**: Handles 100+ concurrent sessions without degradation

### Example Output
```
BenchmarkConnectionEstablishment-8        500      3245678 ns/op
BenchmarkAuthenticationPublicKey-8        500      3289012 ns/op     308.5 auths/sec
BenchmarkSessionCreation-8               1000      1234567 ns/op     810.2 sessions/sec
BenchmarkCommandExecution-8               500      2345678 ns/op     426.3 commands/sec
BenchmarkDataTransferSmall-8             2000       567890 ns/op       1.80 MB/s
BenchmarkDataTransferLarge-8              100     10234567 ns/op      97.65 MB/s
BenchmarkConcurrentSessions/Sessions_1    1000      1234567 ns/op     810.2 ops/sec
BenchmarkConcurrentSessions/Sessions_100   500      3456789 ns/op     289.3 ops/sec
BenchmarkMemoryUsagePerConnection-8       500      2345678 ns/op  1234567 B/op  12345 allocs/op
```

### Metrics Explained
- **ns/op**: Nanoseconds per operation (lower is better)
- **auths/sec, sessions/sec**: Throughput measurements
- **MB/s**: Data transfer rate
- **B/op**: Bytes allocated per operation
- **allocs/op**: Number of allocations per operation

## Troubleshooting

### Server Not Available
If benchmarks skip with "Server not available":
1. Verify server is running: `nc -zv localhost 2222`
2. Check logs: `journalctl -u sshd-go -f`
3. Test manual connection: `ssh -p 2222 -i test/testdata/test_rsa testuser@localhost`

### Authentication Failed
1. Verify authorized_keys: `sudo cat /home/testuser/.ssh/authorized_keys`
2. Check file permissions (must be 600)
3. Test key manually: `ssh -v -p 2222 -i test/testdata/test_rsa testuser@localhost`

### Performance Issues
1. Run benchmarks with longer duration: `-benchtime=30s`
2. Check system load: `uptime`
3. Disable swap: `sudo swapoff -a` (for consistent results)
4. Run with CPU profiling to identify bottlenecks

## Continuous Integration

### GitHub Actions Example
```yaml
- name: Performance Benchmarks
  run: |
    # Setup
    ssh-keygen -t rsa -b 2048 -f test/testdata/test_rsa -N ""
    
    # Start server in background
    ./sshd -D -p 2222 &
    sleep 2
    
    # Run benchmarks
    cd test && go test -bench=. -benchtime=5s
```

### Baseline Tracking
Store benchmark results in CI to track performance regression:
```bash
# Save baseline
go test -bench=. -benchtime=10s | tee baseline.txt

# Compare on each run
go test -bench=. -benchtime=10s > current.txt
benchstat baseline.txt current.txt
```

## Contributing

When adding new benchmarks:
1. Follow existing patterns using `testing.B`
2. Use `setupBenchmark()` helper for initialization
3. Call `b.ResetTimer()` before measured operations
4. Call `b.ReportMetric()` for custom metrics
5. Add `b.Helper()` to helper functions
6. Document what the benchmark measures
7. Ensure benchmark can run standalone with `go test -bench=BenchmarkName`

## Library Justification

**Why golang.org/x/crypto/ssh?**
- Standard library maintained by Go team
- Already used throughout sshd-go project
- Identical to what OpenSSH clients use internally
- Zero additional dependencies
- Proven reliability and performance
- Compatible with both OpenSSH and sshd-go servers

This choice aligns with the project's library-first philosophy: use mature, well-tested libraries rather than custom implementations.
