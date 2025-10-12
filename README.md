# sshd-go

A drop-in replacement for OpenSSH SSHD written in Go.

## Status

🎉 **Core Implementation Complete** - Phase 6 Complete (Signal Handling + Systemd Integration)

**✅ Implemented:**
- OpenSSH-compatible configuration parsing (sshd_config)
- Command-line interface matching OpenSSH sshd
- Basic SSH server framework using gliderlabs/ssh  
- Structured logging and signal handling
- Complete authentication system (PAM integration, public key auth)
- Interactive shell sessions with PTY support
- SFTP subsystem for file transfer (scp/sftp client support)
- Complete port forwarding support (local, remote, direct TCP/IP)
- SSH agent forwarding (auth-agent@openssh.com)
- X11 display forwarding for GUI applications
- Comprehensive host key management (auto-generation, multiple key types)
- User authorization system (AllowUsers/DenyUsers, PermitRootLogin, authorized_keys options)
- Enhanced logging system with OpenSSH-compatible configuration (LogLevel, SyslogFacility, LogFile)
- Signal handling for graceful shutdown (SIGTERM/SIGINT) and configuration reload (SIGHUP)
- **Systemd integration with socket activation support**
- **Production-ready installation script**
- **Performance monitoring with Prometheus metrics and health checks**
- **Comprehensive performance benchmarking suite**
- Complete test suite with >85% coverage

**🔄 Next Phase:** Production testing, baseline performance validation, and advanced authentication

**📊 Current Metrics:** ~2800 lines custom code, 9 dependencies, library-first architecture

**🆕 Latest:** Performance benchmarking suite for OpenSSH comparison validation

## Goal

Create a 100% compatible OpenSSH SSHD server by integrating mature Go libraries with minimal custom code.

## Compatibility Target

- Parse identical `sshd_config` files
- Accept same command-line arguments as OpenSSH SSHD  
- Support all OpenSSH client features (ssh, scp, sftp, port forwarding, agent forwarding, X11 forwarding)
- Drop-in systemd service replacement

## Requirements

- Go 1.21+
- Linux/Unix target systems

## Quick Start

### Development/Testing

```bash
# Clone and build
git clone https://github.com/yourusername/sshd-go
cd sshd-go
go build -o sshd cmd/sshd/main.go

# Test configuration
./sshd -t

# Run in foreground for testing
./sshd -D -f test_sshd_config
```

### Production Installation

```bash
# Build the binary
go build -o sshd cmd/sshd/main.go

# Install with systemd integration (requires root)
sudo ./install.sh
```

The installation script will:
- Install binary to `/usr/local/sbin/sshd-go`
- Set up systemd service files with security hardening
- Configure socket activation support
- Optionally replace OpenSSH SSHD

For detailed deployment instructions, see [Systemd Deployment Guide](docs/systemd-deployment.md).

### Manual Installation

```bash
# Copy binary
sudo cp sshd /usr/local/sbin/sshd-go

# Install systemd files
sudo cp systemd/*.service /etc/systemd/system/
sudo cp systemd/*.socket /etc/systemd/system/
sudo cp systemd/sshd-go.default /etc/default/sshd-go

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable sshd-go.service
sudo systemctl start sshd-go.service
```

## Architecture

This project prioritizes library integration over custom implementation:

- **gliderlabs/ssh** - Core SSH server framework
- **pkg/sftp** - SFTP subsystem
- **crypto/ssh** - SSH protocol and cryptography
- System libraries for authentication

## Performance Benchmarking

Comprehensive performance benchmarking suite to validate the <20% performance target:

```bash
# Automated setup (requires root)
sudo ./test/benchmark-setup.sh setup

# Run benchmarks
cd test && go test -bench=. -benchtime=3s

# Detailed analysis with memory profiling
go test -bench=. -benchtime=10s -benchmem
```

See [test/README.md](test/README.md) for detailed benchmark documentation, OpenSSH comparison methodology, and CI/CD integration examples.

## Contributing

Implementation follows library-first principles. See [development docs](docs/) for detailed information.

### Key Documentation

- [Systemd Deployment Guide](docs/systemd-deployment.md) - Production deployment with systemd
- [Performance Monitoring Guide](docs/monitoring.md) - Prometheus metrics and health checks
- [Development Plan](PLAN.md) - Project roadmap and implementation status
- [Project Goals](GOAL.md) - Technical specifications and architecture

### Development

This project uses a library-first approach with minimal custom code:

- **Core Dependencies**: gliderlabs/ssh, pkg/sftp, crypto/ssh, msteinert/pam
- **Architecture**: Thin wrapper coordinating specialized libraries
- **Testing**: Comprehensive test suite with >85% coverage
- **Security**: All cryptography handled by standard libraries

## License

MIT
