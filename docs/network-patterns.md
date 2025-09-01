# Network Interface Patterns

This document explains the network interface patterns that must be followed throughout the go-sshd project to ensure testability, flexibility, and maintainability.

## Core Principle

**Always use Go network interface types instead of concrete types**. This enhances testability by allowing easy mocking and provides flexibility with different network implementations.

## Key Interface Types

### Connection Interfaces
- ✅ **USE**: `net.Conn` - Interface for stream connections (TCP, Unix sockets, etc.)
- ❌ **AVOID**: `*net.TCPConn`, `*net.UnixConn` - Concrete implementations

### Address Interfaces  
- ✅ **USE**: `net.Addr` - Interface for network addresses
- ❌ **AVOID**: `*net.TCPAddr`, `*net.UDPAddr`, `*net.UnixAddr` - Concrete implementations

### Packet Connection Interfaces
- ✅ **USE**: `net.PacketConn` - Interface for packet connections (UDP, etc.)
- ❌ **AVOID**: `*net.UDPConn` - Concrete implementations

### Listener Interfaces
- ✅ **USE**: `net.Listener` - Interface for stream listeners
- ❌ **AVOID**: `*net.TCPListener`, `*net.UnixListener` - Concrete implementations

## SSH Server Application

### Port Forwarding Implementation

When implementing SSH port forwarding (likely future work), use interface types:

```go
// CORRECT: Use interface types
func handlePortForward(client net.Conn, targetAddr net.Addr) error {
    // Connect to target using interface type
    target, err := net.Dial(targetAddr.Network(), targetAddr.String())
    if err != nil {
        return err
    }
    defer target.Close()
    
    // Both client and target are net.Conn interfaces
    go io.Copy(target, client)
    io.Copy(client, target)
    return nil
}

// INCORRECT: Using concrete types
func handlePortForwardBad(client *net.TCPConn, targetAddr *net.TCPAddr) error {
    // This limits flexibility and testability
    target, err := net.DialTCP("tcp", nil, targetAddr)
    // ... rest of implementation
}
```

### Connection Handling

For SSH connection handling, accept interface types:

```go
// CORRECT: Accept any connection type
func handleSSHConnection(conn net.Conn) {
    // Log connection info using interface methods
    logger.Infof("New connection from %s to %s", 
        conn.RemoteAddr().String(), 
        conn.LocalAddr().String())
    
    // Pass to SSH server (gliderlabs/ssh handles the rest)
    // ...
}

// INCORRECT: Limiting to specific connection types  
func handleSSHConnectionBad(conn *net.TCPConn) {
    // This prevents testing with mocks or other connection types
}
```

### Configuration and Parsing

Store addresses as interfaces in configuration:

```go
type ServerConfig struct {
    // CORRECT: Can hold any address type
    ListenAddresses []net.Addr
    
    // For parsing from strings (config files)
    ListenAddressStrings []string
}

// CORRECT: Return interface type
func parseListenAddress(addr string) (net.Addr, error) {
    return net.ResolveTCPAddr("tcp", addr)
}

// INCORRECT: Return concrete type
func parseListenAddressBad(addr string) (*net.TCPAddr, error) {
    return net.ResolveTCPAddr("tcp", addr)
}
```

## Testing Benefits

Using interface types enables easy mocking for tests:

```go
func TestSSHHandler(t *testing.T) {
    // Create mock connection implementing net.Conn
    mockConn := &mockConnection{
        localAddr:  mockAddr{"tcp", "127.0.0.1:22"},
        remoteAddr: mockAddr{"tcp", "192.168.1.100:12345"},
    }
    
    // Test handler with mock - no real network needed
    handleSSHConnection(mockConn)
    
    // Verify expected behavior...
}
```

## Implementation Guidelines

1. **Function Parameters**: Always accept interface types
2. **Return Values**: Always return interface types where possible
3. **Struct Fields**: Use interface types for network-related fields
4. **Type Assertions**: Avoid type assertions unless absolutely necessary
5. **Configuration**: Parse to concrete types but store as interfaces

## Real-World Applications

### Current Codebase
The current codebase doesn't directly handle network connections (gliderlabs/ssh handles this), but when adding features like:
- Port forwarding
- Custom connection handling  
- Network diagnostics
- Connection pooling

These patterns must be followed.

### Future Features
- **SOCKS proxy support**: Use `net.Conn` for all connections
- **Custom forwarding**: Accept `net.Addr` for destination addresses
- **Connection monitoring**: Store connections as `net.Conn` interfaces
- **Protocol detection**: Work with `net.Conn` regardless of transport

## Verification

The `pkg/network/` package provides examples and tests demonstrating these patterns. All new network-related code should follow these examples.

Run tests to verify pattern compliance:
```bash
go test ./pkg/network/ -v
```
