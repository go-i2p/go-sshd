# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisory** (Preferred): 
   - Navigate to the repository's Security tab
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email**: 
   - Send details to the maintainers (see repository contacts)
   - Include "SECURITY" in the subject line

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., authentication bypass, DoS, code injection)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### Response Timeline

We are committed to responding to security reports promptly:

- **Initial Response**: Within 24 hours
- **Confirmation**: Within 48 hours for critical/high severity issues
- **Fix Timeline**: 
  - Critical: 24-48 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release cycle
- **Public Disclosure**: After fix is released and users have had reasonable time to update (typically 7-14 days)

## Security Update Process

When a security vulnerability is reported and confirmed:

1. **Assessment**: We assess the severity and impact of the vulnerability
2. **Fix Development**: We develop a fix in a private repository
3. **Testing**: The fix undergoes thorough testing including:
   - Unit tests
   - Integration tests with OpenSSH clients
   - Security-specific test cases
4. **Release**: We release a patch version with the security fix
5. **Advisory**: We publish a GitHub Security Advisory with:
   - CVE number (if applicable)
   - Affected versions
   - Fixed version
   - Mitigation steps
   - Credits to the reporter
6. **Notification**: We notify users through:
   - GitHub release notes
   - Security advisory
   - README update

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest patch version
2. **Monitor Advisories**: Watch the repository for security advisories
3. **Automated Scanning**: Enable Dependabot alerts in your fork
4. **Configuration Review**: Follow the security guidelines in the documentation
5. **Principle of Least Privilege**: Run the SSH server with minimal required permissions

### For Developers

1. **Dependency Updates**: Regularly update dependencies using `go get -u`
2. **Vulnerability Scanning**: Run security scans before commits:
   ```bash
   ./security-audit.sh --quick
   ```
3. **Code Review**: All code changes require security-conscious review
4. **Testing**: Maintain >80% test coverage including security test cases
5. **No Custom Crypto**: Never implement custom cryptographic functions

## Security Scanning

This project uses multiple security scanning tools:

### Automated Scans

- **govulncheck**: Official Go vulnerability scanner (runs on every push)
- **Trivy**: Container and filesystem vulnerability scanner
- **Dependabot**: Automated dependency updates with security alerts
- **CodeQL**: Semantic code analysis for security issues

### Manual Scans

Run the security audit script:

```bash
# Quick scan
./security-audit.sh --quick

# Full audit
./security-audit.sh --full

# Install scanning tools
./security-audit.sh --install
```

## Known Security Considerations

### Architecture

- **Zero Custom Cryptography**: All cryptographic operations use `golang.org/x/crypto`
- **Zero Custom Protocol**: All SSH protocol handling uses `gliderlabs/ssh`
- **PAM Integration**: Password authentication delegates to system PAM
- **Minimal Attack Surface**: <3000 lines of custom code

### Dependencies

All dependencies are:
- From trusted sources (Go team, Google, CNCF, established maintainers)
- Regularly updated and monitored for vulnerabilities
- Well-maintained with active security response teams
- Listed with security analysis in [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

### Configuration Security

Follow these configuration best practices:

1. **Disable Root Login**: Set `PermitRootLogin no` unless required
2. **Public Key Only**: Disable password authentication in production
3. **Restrict Users**: Use `AllowUsers` to limit SSH access
4. **Strong Algorithms**: Use modern crypto (Ed25519, ECDSA)
5. **Monitor Logs**: Enable comprehensive logging
6. **Firewall**: Use firewall rules to restrict SSH access
7. **Port Configuration**: Consider using non-standard ports to reduce automated attacks

## Security Audit History

Security audits are documented in [SECURITY_AUDIT.md](SECURITY_AUDIT.md):

- **October 2025**: Initial comprehensive security audit (PASS)
- Quarterly audits scheduled
- Continuous automated monitoring enabled

## Compliance

### Standards

- Uses NIST-approved cryptographic algorithms
- Follows CIS SSH Server hardening guidelines
- Compatible with FIPS 140-2 algorithms (not certified)

### Licenses

All dependencies use permissive licenses (MIT, Apache 2.0, BSD) compatible with commercial use.

## Security Features

### Authentication

- ✅ Public key authentication (RSA, ECDSA, Ed25519)
- ✅ Password authentication (via PAM)
- ✅ Keyboard-interactive authentication (MFA support via PAM)
- ✅ Certificate-based authentication (SSH certificates)
- ✅ Authorized keys with restrictions (from, command, no-port-forwarding, etc.)

### Authorization

- ✅ User access control (AllowUsers, DenyUsers, AllowGroups, DenyGroups)
- ✅ Root login policies (yes, no, prohibit-password, forced-commands-only)
- ✅ Per-key restrictions via authorized_keys options
- ✅ Source address validation (CIDR and wildcard patterns)

### Data Protection

- ✅ Strong encryption algorithms (AES-GCM, ChaCha20-Poly1305)
- ✅ Modern key exchange (Curve25519, ECDH)
- ✅ Perfect forward secrecy
- ✅ Host key verification

### Monitoring

- ✅ Comprehensive logging (authentication, sessions, errors)
- ✅ Prometheus metrics for security monitoring
- ✅ Failed authentication tracking
- ✅ Session activity logging

## Resources

- [Go Security Policy](https://go.dev/security)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [CIS SSH Benchmarks](https://www.cisecurity.org/)
- [OpenSSH Security Advisories](https://www.openssh.com/security.html)

## Credits

We acknowledge and thank security researchers who responsibly disclose vulnerabilities:

- (List will be updated as vulnerabilities are reported and fixed)

## Questions?

For security-related questions that are not sensitive, please open a GitHub Discussion in the Security category.

For sensitive security matters, use the private reporting methods described above.
