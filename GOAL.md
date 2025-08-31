# PROJECT: Drop-in OpenSSH SSHD Replacement

## OBJECTIVE:
Build a 100% OpenSSH-compatible SSHD server by **assembling existing libraries** with minimal glue code. No protocol implementations, no custom authentication—pure integration work.

## TECHNICAL SPECIFICATIONS:
- Language: Go
- Type: Server Binary (drop-in replacement)
- Architecture: Thin wrapper orchestrating mature libraries
- Deployment: Single static binary, systemd-ready

## MANDATORY LIBRARY STACK:
```
CORE SSH:     gliderlabs/ssh              # Base SSH server framework
CONFIG:       google/shlex + custom       # OpenSSH config parsing
SFTP:         pkg/sftp                    # SFTP subsystem (complete)
AUTH:         crypto/ssh + system libs    # Key/password authentication  
FORWARDING:   net + gorilla/websocket     # Port forwarding via existing conn handling
X11:          Available X11 Go bindings   # X11 forwarding integration
PAM:          msteinert/pam               # System authentication
LOGGING:      sirupsen/logrus             # Structured logging
CLI:          spf13/cobra + spf13/viper   # Args parsing and config
```

## IMPLEMENTATION STRATEGY:

### Phase 1: Minimal Viable Server (Week 1)
**TASK**: Wire gliderlabs/ssh with basic shell sessions
```go
// Target: 200 lines max in main.go
// Use gliderlabs/ssh examples as starting point
// Accept connections, spawn shell, that's it
```
**VALIDATION**: Can SSH in and run commands

### Phase 2: Configuration Layer (Week 1)
**TASK**: Parse sshd_config using existing config parsers
```go
// Find existing sshd_config parsers or adapt OpenSSH config format
// Use github.com/google/shlex for shell-style parsing
// Map parsed config to gliderlabs/ssh server options
```
**VALIDATION**: Reads standard sshd_config files without errors

### Phase 3: Authentication Integration (Week 1)
**TASK**: Wire existing auth libraries to gliderlabs/ssh callbacks
```go
// Public key: Use crypto/ssh.ParseAuthorizedKey
// Password: Use msteinert/pam for system auth
// Keyboard-interactive: Wrap PAM conversation
```
**VALIDATION**: All OpenSSH auth methods work

### Phase 4: SFTP Subsystem (Week 1)
**TASK**: Register pkg/sftp as subsystem handler
```go
// pkg/sftp has complete SFTP server implementation
// Register as "sftp" subsystem in gliderlabs/ssh
// Map filesystem operations to host filesystem
```
**VALIDATION**: scp/sftp clients work identically to OpenSSH

### Phase 5: Port Forwarding (Week 2)
**TASK**: Implement using net package connection forwarding
```go
// Local forwarding: Accept local connections, forward via SSH
// Remote forwarding: Accept SSH requests, dial local connections
// Use existing Go connection copying patterns
```
**VALIDATION**: ssh -L, -R, -D all function identically

### Phase 6: X11 + Agent Forwarding (Week 2)  
**TASK**: Integrate existing X11/agent forwarding libraries
```go
// Find mature X11 forwarding Go implementation
// Use existing SSH agent protocol libraries
// Wire to gliderlabs/ssh channel handling
```
**VALIDATION**: X11 apps and ssh-agent work through connection

## CODE REQUIREMENTS:

### Library-First Rules:
```
1. Search go.pkg.dev BEFORE writing any code
2. If >50 lines implement a feature, find a library
3. Document library evaluation in README
4. Prefer boring, stable libraries over new/trendy
5. Every import must justify why it was chosen
```

### Integration Patterns:
```go
// Example: Don't implement SFTP
❌ NEVER:
func (s *Server) handleSFTP(channel ssh.Channel) {
    // 500+ lines of SFTP protocol implementation
}

✅ ALWAYS:
func (s *Server) handleSFTP(channel ssh.Channel) {
    server, err := sftp.NewServer(channel)
    if err != nil { return err }
    return server.Serve()
}
```

### Wrapper Strategy:
```go
// Your code should be 90% type conversion and error handling
type SSHDServer struct {
    sshServer   *ssh.Server      // gliderlabs/ssh
    config      *SSHDConfig      // parsed sshd_config  
    authHandler *AuthHandler     // wraps system auth
    ftpHandler  *sftp.Server     // pkg/sftp
}
```

## PROJECT STRUCTURE:
```
cmd/sshd/
  main.go                    # 100 lines max - CLI + server start
internal/
  config/
    parser.go               # Wrap existing config parsers
  handlers/
    auth.go                 # Thin wrapper over crypto/ssh + PAM
    sftp.go                 # Register pkg/sftp as subsystem
    shell.go                # Minimal PTY handling
    forwarding.go           # Port forwarding via net package
go.mod                      # All dependencies explicitly versioned
README.md                   # Library choices documented
```

## QUALITY GATES:

### Code Volume Limits:
- Total custom code: <2000 lines (excluding tests)
- Largest file: <300 lines
- Any file >200 lines requires library search justification
- If implementing >100 lines for a feature, stop and find a library

### Library Integration Success:
- [ ] gliderlabs/ssh handles all SSH protocol details  
- [ ] pkg/sftp handles all SFTP protocol details
- [ ] crypto/ssh handles all cryptographic operations
- [ ] System libraries handle all authentication
- [ ] Standard net package handles all forwarding
- [ ] Zero custom protocol implementations

### Compatibility Validation:
- [ ] Drop-in replacement for OpenSSH SSHD binary
- [ ] All sshd_config directives parsed correctly
- [ ] OpenSSH clients connect without any changes
- [ ] ssh, scp, sftp all function identically
- [ ] Performance within 20% of OpenSSH (library overhead acceptable)

## SUCCESS METRICS:
1. **Lines of Code**: <2000 lines total custom code
2. **Dependencies**: 8-12 mature libraries doing the heavy lifting  
3. **Development Time**: 4-6 weeks with testing
4. **Maintenance**: Security updates = dependency updates only
5. **Compatibility**: 100% OpenSSH client compatibility

## ANTI-PATTERNS TO AVOID:
```
❌ Implementing SSH protocol details
❌ Custom cryptographic code  
❌ Parsing SSH packets manually
❌ Implementing authentication protocols
❌ Writing SFTP protocol handlers
❌ Custom configuration formats
❌ Reinventing connection management
```

## DELIVERY:
- Single static binary: `sshd`
- Library integration documentation
- Systemd service files
- OpenSSH migration guide
- Dependency security audit report