# sshd-go

A drop-in replacement for OpenSSH SSHD written in Go.

## Status

🚧 **In Development** - Not ready for production use.

## Goal

Create a 100% compatible OpenSSH SSHD server by integrating mature Go libraries with minimal custom code.

## Compatibility Target

- Parse identical `sshd_config` files
- Accept same command-line arguments as OpenSSH SSHD  
- Support all OpenSSH client features (ssh, scp, sftp, port forwarding)
- Drop-in systemd service replacement

## Requirements

- Go 1.21+
- Linux/Unix target systems

## Quick Start

```bash
# Clone and build (when ready)
git clone https://github.com/yourusername/sshd-go
cd sshd-go
go build -o sshd cmd/sshd/main.go

# Replace OpenSSH SSHD (when ready)
sudo systemctl stop sshd
sudo cp sshd /usr/local/sbin/sshd-go
# Configure and test...
```

## Architecture

This project prioritizes library integration over custom implementation:
- **gliderlabs/ssh** - Core SSH server framework
- **pkg/sftp** - SFTP subsystem
- **crypto/ssh** - SSH protocol and cryptography
- System libraries for authentication

## Contributing

Implementation follows library-first principles. See [development docs](docs/) when available.

## License

MIT