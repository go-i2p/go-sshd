# Systemd Deployment Guide

This guide covers deploying sshd-go with systemd integration, including service management, socket activation, and migration from OpenSSH.

## Quick Installation

The easiest way to install sshd-go with systemd integration is using the included installation script:

```bash
# Build the binary
go build -o sshd cmd/sshd/main.go

# Run installation script (requires root privileges)
sudo ./install.sh
```

The installation script will:
- Install the binary to `/usr/local/sbin/sshd-go`
- Install systemd service files to `/etc/systemd/system/`
- Configure default startup options in `/etc/default/sshd-go`
- Optionally stop and disable OpenSSH sshd
- Enable and start the sshd-go service

## Manual Installation

If you prefer manual installation or need custom configuration:

### 1. Install Binary

```bash
# Copy binary to system location
sudo cp sshd /usr/local/sbin/sshd-go
sudo chmod 755 /usr/local/sbin/sshd-go
```

### 2. Install Systemd Files

```bash
# Copy service files
sudo cp systemd/sshd-go.service /etc/systemd/system/
sudo cp systemd/sshd-go.socket /etc/systemd/system/
sudo cp systemd/sshd-go@.service /etc/systemd/system/
sudo cp systemd/sshd-go-keygen.service /etc/systemd/system/

# Copy default configuration
sudo cp systemd/sshd-go.default /etc/default/sshd-go

# Set proper permissions
sudo chmod 644 /etc/systemd/system/sshd-go.*
sudo chmod 644 /etc/default/sshd-go
```

### 3. Configure and Enable

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service on boot
sudo systemctl enable sshd-go.service

# Start service
sudo systemctl start sshd-go.service
```

## Service Management

### Basic Service Commands

```bash
# Start the service
sudo systemctl start sshd-go.service

# Stop the service
sudo systemctl stop sshd-go.service

# Restart the service
sudo systemctl restart sshd-go.service

# Reload configuration (SIGHUP)
sudo systemctl reload sshd-go.service

# Check service status
sudo systemctl status sshd-go.service

# View service logs
sudo journalctl -u sshd-go.service

# Follow logs in real-time
sudo journalctl -f -u sshd-go.service
```

### Enable/Disable Auto-Start

```bash
# Enable automatic startup on boot
sudo systemctl enable sshd-go.service

# Disable automatic startup
sudo systemctl disable sshd-go.service

# Check if enabled
sudo systemctl is-enabled sshd-go.service
```

## Socket Activation

sshd-go supports systemd socket activation, which allows on-demand service startup when connections are received.

### Enable Socket Activation

```bash
# Stop regular service (if running)
sudo systemctl stop sshd-go.service
sudo systemctl disable sshd-go.service

# Enable socket activation
sudo systemctl enable sshd-go.socket
sudo systemctl start sshd-go.socket
```

### Socket Management

```bash
# Start socket listener
sudo systemctl start sshd-go.socket

# Stop socket listener
sudo systemctl stop sshd-go.socket

# Check socket status
sudo systemctl status sshd-go.socket

# List active sockets
sudo systemctl list-sockets | grep sshd-go
```

### Socket vs Service Mode

| Mode | Use Case | Pros | Cons |
|------|----------|------|------|
| **Service** | High-traffic servers | Lower latency, always ready | Uses more memory |
| **Socket** | Low-traffic/development | Saves resources, on-demand | Slight connection delay |

## Configuration

### Default Configuration File

Edit `/etc/default/sshd-go` to customize startup options:

```bash
# Command line options for sshd-go
SSHD_OPTS=""

# Enable debugging (uncomment for troubleshooting)
# SSHD_OPTS="-f /etc/ssh/sshd_config -D -e"

# Use custom configuration file
# SSHD_OPTS="-f /path/to/custom/sshd_config -D"
```

### SSH Configuration

sshd-go uses the standard OpenSSH configuration file at `/etc/ssh/sshd_config`. No changes are required for basic operation.

### Test Configuration

Before starting the service, always test your configuration:

```bash
# Test configuration
sudo /usr/local/sbin/sshd-go -t

# Test with specific config file
sudo /usr/local/sbin/sshd-go -t -f /etc/ssh/sshd_config
```

## Migration from OpenSSH

### Pre-Migration Checklist

1. **Backup Configuration**
   ```bash
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
   ```

2. **Test Compatibility**
   ```bash
   # Test current config with sshd-go
   sudo /usr/local/sbin/sshd-go -t -f /etc/ssh/sshd_config
   ```

3. **Note Current Settings**
   ```bash
   # Check current SSH service status
   sudo systemctl status sshd
   
   # Check which port SSH is using
   sudo ss -tlnp | grep :22
   ```

### Migration Steps

1. **Stop OpenSSH (Recommended)**
   ```bash
   sudo systemctl stop sshd
   sudo systemctl disable sshd
   ```

2. **Install sshd-go**
   ```bash
   sudo ./install.sh
   ```

3. **Verify Operation**
   ```bash
   # Check service status
   sudo systemctl status sshd-go.service
   
   # Test SSH connection (from another terminal/machine)
   ssh user@hostname
   ```

4. **Rollback if Needed**
   ```bash
   # If issues occur, quickly rollback
   sudo systemctl stop sshd-go.service
   sudo systemctl start sshd
   ```

### Coexistence Setup

To run both OpenSSH and sshd-go simultaneously (for testing):

1. **Configure Different Ports**
   ```bash
   # Edit OpenSSH config
   sudo sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config
   
   # Edit sshd-go config for different port
   echo "Port 2222" | sudo tee -a /etc/ssh/sshd_config_go
   ```

2. **Start Both Services**
   ```bash
   # Start OpenSSH on port 22
   sudo systemctl start sshd
   
   # Start sshd-go on port 2222
   sudo SSHD_OPTS="-f /etc/ssh/sshd_config_go" systemctl start sshd-go.service
   ```

## Security Considerations

### Systemd Security Features

The provided service files include security hardening:

- `NoNewPrivileges=true` - Prevents privilege escalation
- `ProtectSystem=strict` - Read-only filesystem access
- `ProtectHome=true` - Restricts access to user home directories
- `PrivateTmp=true` - Isolated temporary directory
- Capability restrictions limit what the process can do

### SELinux Compatibility

If using SELinux, you may need to create appropriate contexts:

```bash
# Set proper SELinux context for binary
sudo semanage fcontext -a -t ssh_exec_t "/usr/local/sbin/sshd-go"
sudo restorecon -v /usr/local/sbin/sshd-go
```

### Firewall Configuration

Ensure your firewall allows SSH connections:

```bash
# For firewalld
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload

# For ufw
sudo ufw allow ssh

# For iptables
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

## Troubleshooting

### Common Issues

1. **Service Fails to Start**
   ```bash
   # Check detailed logs
   sudo journalctl -u sshd-go.service -n 50
   
   # Test configuration
   sudo /usr/local/sbin/sshd-go -t
   ```

2. **Permission Denied Errors**
   ```bash
   # Check binary permissions
   ls -la /usr/local/sbin/sshd-go
   
   # Check host key permissions
   ls -la /etc/ssh/ssh_host_*
   ```

3. **Port Already in Use**
   ```bash
   # Check what's using port 22
   sudo ss -tlnp | grep :22
   
   # Kill conflicting process or change port
   ```

4. **Socket Activation Not Working**
   ```bash
   # Check socket status
   sudo systemctl status sshd-go.socket
   
   # Verify socket is listening
   sudo ss -tlnp | grep :22
   ```

### Debug Mode

Enable debug output for troubleshooting:

```bash
# Edit /etc/default/sshd-go
SSHD_OPTS="-D -e"

# Restart service
sudo systemctl restart sshd-go.service

# Watch logs
sudo journalctl -f -u sshd-go.service
```

### Log Analysis

```bash
# Authentication failures
sudo journalctl -u sshd-go.service | grep "authentication failure"

# Connection attempts
sudo journalctl -u sshd-go.service | grep "connection from"

# Configuration errors
sudo journalctl -u sshd-go.service | grep "error"
```

## Performance Tuning

### Resource Limits

Adjust systemd limits in the service file:

```ini
[Service]
LimitNOFILE=65536      # Maximum open files
LimitNPROC=32768       # Maximum processes
```

### Socket Configuration

For high-traffic scenarios, tune socket settings:

```ini
[Socket]
MaxConnections=64      # Concurrent connections
Backlog=128           # Listen queue size
```

### Logging Performance

Reduce logging overhead in production:

```bash
# Edit sshd_config
LogLevel QUIET
```

## Advanced Features

### Custom Service Files

Create custom service files for specific deployments:

```bash
# Copy and modify
sudo cp /etc/systemd/system/sshd-go.service /etc/systemd/system/sshd-go-custom.service

# Edit as needed
sudo systemctl edit sshd-go-custom.service
```

### Multiple Instances

Run multiple sshd-go instances on different ports:

```bash
# Create instance-specific config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_alt
sudo sed -i 's/Port 22/Port 2222/' /etc/ssh/sshd_config_alt

# Start with custom config
sudo systemctl start sshd-go@alt.service
```

### Monitoring Integration

Integrate with monitoring systems:

```bash
# Enable metrics collection
SSHD_OPTS="-D --metrics-port 9100"

# Monitor with systemd
sudo systemctl status sshd-go.service
```

## Uninstallation

To completely remove sshd-go:

```bash
# Using the installation script
sudo ./install.sh uninstall

# Or manually
sudo systemctl stop sshd-go.service
sudo systemctl disable sshd-go.service
sudo rm -f /usr/local/sbin/sshd-go
sudo rm -f /etc/systemd/system/sshd-go.*
sudo rm -f /etc/default/sshd-go
sudo systemctl daemon-reload
```

To restore OpenSSH:

```bash
sudo systemctl enable sshd
sudo systemctl start sshd
```

## Further Reading

- [systemd.service(5)](https://man7.org/linux/man-pages/man5/systemd.service.5.html) - Service unit configuration
- [systemd.socket(5)](https://man7.org/linux/man-pages/man5/systemd.socket.5.html) - Socket unit configuration  
- [sshd_config(5)](https://man.openbsd.org/sshd_config) - SSH daemon configuration
- [sshd-go Configuration Guide](../README.md) - Main project documentation