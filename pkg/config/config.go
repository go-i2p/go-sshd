// Package config provides OpenSSH-compatible configuration parsing.
// This package wraps google/shlex and other libraries to parse sshd_config
// files with full OpenSSH compatibility.
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

// ValidationLevel represents the severity of a validation issue.
type ValidationLevel int

const (
	// ValidationInfo indicates informational messages
	ValidationInfo ValidationLevel = iota
	// ValidationWarning indicates configuration issues that should be reviewed
	ValidationWarning
	// ValidationError indicates configuration errors that prevent operation
	ValidationError
)

// String returns the string representation of validation level.
func (v ValidationLevel) String() string {
	switch v {
	case ValidationInfo:
		return "INFO"
	case ValidationWarning:
		return "WARNING"
	case ValidationError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ValidationIssue represents a single validation problem or observation.
type ValidationIssue struct {
	Level      ValidationLevel `json:"level"`
	Directive  string          `json:"directive"`
	Message    string          `json:"message"`
	Suggestion string          `json:"suggestion,omitempty"`
	LineNumber int             `json:"line_number,omitempty"`
}

// ValidationResult contains the results of configuration validation.
type ValidationResult struct {
	Valid      bool              `json:"valid"`
	Issues     []ValidationIssue `json:"issues"`
	ErrorCount int               `json:"error_count"`
	WarnCount  int               `json:"warn_count"`
	InfoCount  int               `json:"info_count"`
}

// AddIssue adds a validation issue to the result.
func (vr *ValidationResult) AddIssue(level ValidationLevel, directive, message, suggestion string) {
	issue := ValidationIssue{
		Level:      level,
		Directive:  directive,
		Message:    message,
		Suggestion: suggestion,
	}
	vr.Issues = append(vr.Issues, issue)

	switch level {
	case ValidationError:
		vr.ErrorCount++
		vr.Valid = false
	case ValidationWarning:
		vr.WarnCount++
	case ValidationInfo:
		vr.InfoCount++
	}
}

// Config represents the parsed OpenSSH SSHD configuration.
// This struct maps directly to OpenSSH sshd_config directives.
type Config struct {
	// Connection settings
	Port          int      `json:"port"`
	ListenAddress []string `json:"listen_address"`
	Protocol      []int    `json:"protocol"`

	// Host key settings
	HostKey []string `json:"host_key"`

	// Authentication settings
	PasswordAuthentication       bool     `json:"password_authentication"`
	PubkeyAuthentication         bool     `json:"pubkey_authentication"`
	KbdInteractiveAuthentication bool     `json:"kbd_interactive_authentication"`
	AuthorizedKeysFile           []string `json:"authorized_keys_file"`

	// Certificate authentication settings
	TrustedUserCAKeys []string `json:"trusted_user_ca_keys"` // CA public keys for user certificate validation
	RevokedKeys       []string `json:"revoked_keys"`         // Files containing revoked certificates/keys

	// Session settings
	PermitRootLogin string   `json:"permit_root_login"`
	AllowUsers      []string `json:"allow_users"`
	DenyUsers       []string `json:"deny_users"`

	// Feature settings
	Subsystem            map[string]string `json:"subsystem"`
	AllowTcpForwarding   bool              `json:"allow_tcp_forwarding"`
	AllowAgentForwarding bool              `json:"allow_agent_forwarding"`
	X11Forwarding        bool              `json:"x11_forwarding"`
	X11DisplayOffset     int               `json:"x11_display_offset"`
	X11UseLocalhost      bool              `json:"x11_use_localhost"`
	GatewayPorts         bool              `json:"gateway_ports"`

	// Logging settings
	LogLevel       string `json:"log_level"`
	SyslogFacility string `json:"syslog_facility"`
	LogFile        string `json:"log_file"`

	// Monitoring and metrics settings (extension)
	MetricsEnabled bool   `json:"metrics_enabled"` // Enable Prometheus metrics endpoint
	MetricsAddress string `json:"metrics_address"` // Address for metrics HTTP server (e.g., "127.0.0.1:9100")
}

// Validate performs comprehensive validation of the configuration.
// This method checks all configuration values for correctness, compatibility,
// and potential security issues following OpenSSH validation patterns.
func (c *Config) Validate() *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Validate port configuration
	c.validatePort(result)

	// Validate listen addresses
	c.validateListenAddresses(result)

	// Validate host key paths
	c.validateHostKeys(result)

	// Validate authentication settings
	c.validateAuthentication(result)

	// Validate authorization settings
	c.validateAuthorization(result)

	// Validate logging configuration
	c.validateLogging(result)

	// Validate forwarding settings
	c.validateForwarding(result)

	// Validate subsystem configuration
	c.validateSubsystems(result)

	// Cross-directive validation
	c.validateCrossDependencies(result)

	return result
}

// validatePort checks if the port configuration is valid.
func (c *Config) validatePort(result *ValidationResult) {
	if c.Port < 1 || c.Port > 65535 {
		result.AddIssue(ValidationError, "Port",
			fmt.Sprintf("Port %d is out of valid range (1-65535)", c.Port),
			"Use a port number between 1 and 65535")
		return
	}

	// Warn about privileged ports
	if c.Port < 1024 {
		result.AddIssue(ValidationWarning, "Port",
			fmt.Sprintf("Port %d requires root privileges", c.Port),
			"Consider using a port >= 1024 for non-root operation")
	}

	// Warn about common non-standard ports
	if c.Port != 22 {
		result.AddIssue(ValidationInfo, "Port",
			fmt.Sprintf("Using non-standard SSH port %d", c.Port),
			"Ensure firewall rules allow this port")
	}
}

// validateListenAddresses checks if listen addresses are valid.
func (c *Config) validateListenAddresses(result *ValidationResult) {
	seenAddresses := make(map[string]bool)

	for _, addr := range c.ListenAddress {
		// Check for duplicates
		if seenAddresses[addr] {
			result.AddIssue(ValidationWarning, "ListenAddress",
				fmt.Sprintf("Duplicate listen address: %s", addr),
				"Remove duplicate entries")
			continue
		}
		seenAddresses[addr] = true

		// Validate address format
		if addr == "0.0.0.0" || addr == "::" {
			result.AddIssue(ValidationInfo, "ListenAddress",
				fmt.Sprintf("Listening on all interfaces: %s", addr),
				"Consider binding to specific interfaces for security")
			continue
		}

		// Parse and validate IP address
		ip := net.ParseIP(addr)
		if ip == nil {
			// Try as hostname
			if !isValidHostname(addr) {
				result.AddIssue(ValidationError, "ListenAddress",
					fmt.Sprintf("Invalid IP address or hostname: %s", addr),
					"Use a valid IP address or resolvable hostname")
			}
		}
	}
}

// validateHostKeys checks host key file paths and accessibility.
func (c *Config) validateHostKeys(result *ValidationResult) {
	if len(c.HostKey) == 0 {
		result.AddIssue(ValidationError, "HostKey",
			"No host keys configured",
			"Configure at least one host key file")
		return
	}

	keyTypes := make(map[string]bool)

	for _, keyPath := range c.HostKey {
		// Check if file exists and is readable
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			result.AddIssue(ValidationWarning, "HostKey",
				fmt.Sprintf("Host key file does not exist: %s", keyPath),
				"Ensure the key file exists or will be auto-generated")
		} else if err != nil {
			result.AddIssue(ValidationError, "HostKey",
				fmt.Sprintf("Cannot access host key file: %s (%v)", keyPath, err),
				"Check file permissions and path")
		}

		// Detect key type from filename
		keyType := detectKeyType(keyPath)
		if keyType != "" {
			if keyTypes[keyType] {
				result.AddIssue(ValidationWarning, "HostKey",
					fmt.Sprintf("Multiple %s host keys configured", keyType),
					"Only one key per type is typically needed")
			}
			keyTypes[keyType] = true
		}
	}

	// Recommend modern key types
	if !keyTypes["ed25519"] && !keyTypes["ecdsa"] {
		result.AddIssue(ValidationInfo, "HostKey",
			"Consider using Ed25519 or ECDSA keys for better security",
			"Add Ed25519 keys for modern cryptography")
	}
}

// validateAuthentication checks authentication-related settings.
func (c *Config) validateAuthentication(result *ValidationResult) {
	// Check if at least one authentication method is enabled
	if !c.PasswordAuthentication && !c.PubkeyAuthentication {
		result.AddIssue(ValidationError, "Authentication",
			"No authentication methods enabled",
			"Enable at least one of PasswordAuthentication or PubkeyAuthentication")
	}

	// Security recommendations
	if c.PasswordAuthentication {
		result.AddIssue(ValidationWarning, "PasswordAuthentication",
			"Password authentication enabled - consider disabling for better security",
			"Use public key authentication instead")
	}

	// Validate authorized keys files
	for _, keyFile := range c.AuthorizedKeysFile {
		if strings.Contains(keyFile, "..") {
			result.AddIssue(ValidationError, "AuthorizedKeysFile",
				fmt.Sprintf("Authorized keys file path contains '..': %s", keyFile),
				"Use absolute paths or paths relative to user home")
		}
	}
}

// validateAuthorization checks user authorization settings.
func (c *Config) validateAuthorization(result *ValidationResult) {
	// Validate PermitRootLogin
	validRootLoginValues := []string{"yes", "no", "prohibit-password", "forced-commands-only"}
	isValid := false
	for _, valid := range validRootLoginValues {
		if c.PermitRootLogin == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		result.AddIssue(ValidationError, "PermitRootLogin",
			fmt.Sprintf("Invalid PermitRootLogin value: %s", c.PermitRootLogin),
			"Use one of: yes, no, prohibit-password, forced-commands-only")
	}

	// Security warning for root login
	if c.PermitRootLogin == "yes" {
		result.AddIssue(ValidationWarning, "PermitRootLogin",
			"Root login with password enabled - security risk",
			"Use 'prohibit-password' or 'no' for better security")
	}

	// Check for conflicts between AllowUsers and DenyUsers
	if len(c.AllowUsers) > 0 && len(c.DenyUsers) > 0 {
		// Check for overlapping patterns
		for _, allowUser := range c.AllowUsers {
			for _, denyUser := range c.DenyUsers {
				if allowUser == denyUser {
					result.AddIssue(ValidationWarning, "AllowUsers/DenyUsers",
						fmt.Sprintf("User '%s' appears in both AllowUsers and DenyUsers", allowUser),
						"Remove from one of the lists to avoid conflicts")
				}
			}
		}
	}
}

// validateLogging checks logging configuration settings.
func (c *Config) validateLogging(result *ValidationResult) {
	// LogLevel validation is already done in parseDirective, but add info
	if c.LogLevel == "DEBUG" || c.LogLevel == "DEBUG1" || c.LogLevel == "DEBUG2" || c.LogLevel == "DEBUG3" {
		result.AddIssue(ValidationInfo, "LogLevel",
			"Debug logging enabled - may generate large log files",
			"Consider using INFO or VERBOSE for production")
	}

	// Validate log file path if specified
	if c.LogFile != "" {
		logDir := filepath.Dir(c.LogFile)
		if _, err := os.Stat(logDir); os.IsNotExist(err) {
			result.AddIssue(ValidationError, "LogFile",
				fmt.Sprintf("Log file directory does not exist: %s", logDir),
				"Create the directory or use an existing path")
		}

		// Check if we can write to the log file
		if _, err := os.OpenFile(c.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644); err != nil {
			result.AddIssue(ValidationWarning, "LogFile",
				fmt.Sprintf("Cannot write to log file: %s (%v)", c.LogFile, err),
				"Check directory permissions and disk space")
		}
	}
}

// validateForwarding checks port forwarding settings.
func (c *Config) validateForwarding(result *ValidationResult) {
	if c.AllowTcpForwarding && c.GatewayPorts {
		result.AddIssue(ValidationWarning, "GatewayPorts",
			"GatewayPorts enabled with TCP forwarding - potential security risk",
			"Consider restricting gateway ports in production environments")
	}

	if c.AllowAgentForwarding {
		result.AddIssue(ValidationInfo, "AllowAgentForwarding",
			"SSH agent forwarding enabled",
			"Ensure agent forwarding is needed and secure")
	}

	if c.X11Forwarding {
		result.AddIssue(ValidationInfo, "X11Forwarding",
			"X11 forwarding enabled",
			"Ensure X11 display forwarding is needed and secure")
	}
}

// validateSubsystems checks subsystem configuration.
func (c *Config) validateSubsystems(result *ValidationResult) {
	for name, path := range c.Subsystem {
		// Check if subsystem binary exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			result.AddIssue(ValidationError, "Subsystem",
				fmt.Sprintf("Subsystem '%s' binary not found: %s", name, path),
				"Install the subsystem binary or correct the path")
		} else if err != nil {
			result.AddIssue(ValidationWarning, "Subsystem",
				fmt.Sprintf("Cannot access subsystem '%s' binary: %s (%v)", name, path, err),
				"Check file permissions")
		}

		// Validate common subsystems
		if name == "sftp" && !strings.Contains(path, "sftp") {
			result.AddIssue(ValidationWarning, "Subsystem",
				fmt.Sprintf("SFTP subsystem path may be incorrect: %s", path),
				"Ensure path points to an SFTP server binary")
		}
	}

	// Recommend SFTP subsystem
	if _, hasSFTP := c.Subsystem["sftp"]; !hasSFTP {
		result.AddIssue(ValidationInfo, "Subsystem",
			"No SFTP subsystem configured",
			"Consider adding SFTP subsystem for file transfer support")
	}
}

// validateCrossDependencies checks for configuration conflicts and dependencies.
func (c *Config) validateCrossDependencies(result *ValidationResult) {
	// Check authentication vs authorization conflicts
	if !c.PasswordAuthentication && !c.PubkeyAuthentication && len(c.AllowUsers) > 0 {
		result.AddIssue(ValidationWarning, "Authentication",
			"User restrictions configured but no authentication methods enabled",
			"Enable authentication methods to enforce user restrictions")
	}

	// Check for security-related combinations
	if c.PermitRootLogin == "yes" && c.PasswordAuthentication {
		result.AddIssue(ValidationError, "Security",
			"Root password login enabled - major security risk",
			"Disable PasswordAuthentication or set PermitRootLogin to 'prohibit-password'")
	}
}

// Helper functions

// isValidHostname checks if a string is a valid hostname.
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// IP addresses should be handled separately - reject numeric formats
	if net.ParseIP(hostname) != nil {
		return false
	}

	// Simple hostname validation regex - excludes IP addresses
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return hostnameRegex.MatchString(hostname)
}

// detectKeyType attempts to determine the key type from the file path.
func detectKeyType(keyPath string) string {
	filename := filepath.Base(keyPath)

	if strings.Contains(filename, "ed25519") {
		return "ed25519"
	}
	if strings.Contains(filename, "ecdsa") {
		return "ecdsa"
	}
	if strings.Contains(filename, "rsa") {
		return "rsa"
	}
	if strings.Contains(filename, "dsa") {
		return "dsa"
	}

	return ""
}

// Load reads and parses an OpenSSH sshd_config file.
// This function uses google/shlex for shell-style tokenization
// to maintain full compatibility with OpenSSH config parsing.
func Load(filename string) (*Config, error) {
	// Set defaults matching OpenSSH behavior
	cfg := &Config{
		Port:                         22,
		ListenAddress:                []string{"0.0.0.0"},
		Protocol:                     []int{2},
		HostKey:                      []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"},
		PasswordAuthentication:       true,
		PubkeyAuthentication:         true,
		KbdInteractiveAuthentication: true, // OpenSSH default: yes
		AuthorizedKeysFile:           []string{".ssh/authorized_keys"},
		TrustedUserCAKeys:            []string{},       // OpenSSH default: none
		RevokedKeys:                  []string{},       // OpenSSH default: none
		PermitRootLogin:              "prohibit-password",
		Subsystem:                    make(map[string]string),
		AllowTcpForwarding:           true,
		AllowAgentForwarding:         true,
		X11Forwarding:                false,
		X11DisplayOffset:             10,   // OpenSSH default
		X11UseLocalhost:              true, // OpenSSH default
		GatewayPorts:                 false,
		LogLevel:                     "INFO",
		SyslogFacility:               "AUTH",
		LogFile:                      "", // Empty means stderr/stdout
		MetricsEnabled:               false,
		MetricsAddress:               "127.0.0.1:9100", // Default Prometheus port for node_exporter compatibility
	}

	// Open and parse configuration file
	file, err := os.Open(filename)
	if err != nil {
		// If config file doesn't exist, return defaults
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to open config file %q: %w", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line using shlex for OpenSSH compatibility
		tokens, err := shlex.Split(line)
		if err != nil {
			return nil, fmt.Errorf("config parse error at line %d: %w", lineNum, err)
		}

		if len(tokens) < 2 {
			// Lines with just a directive and no arguments should cause an error
			// when the directive is parsed, so continue to parseDirective
			if len(tokens) == 1 {
				if err := cfg.parseDirective(strings.ToLower(tokens[0]), []string{}); err != nil {
					return nil, fmt.Errorf("config error at line %d: %w", lineNum, err)
				}
			}
			continue
		}

		directive := strings.ToLower(tokens[0])
		args := tokens[1:]

		// Parse directives - minimal set for initial implementation
		if err := cfg.parseDirective(directive, args); err != nil {
			return nil, fmt.Errorf("config error at line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return cfg, nil
}

// parseDirective processes individual configuration directives.
// This method handles the core OpenSSH directives needed for basic operation.
func (c *Config) parseDirective(directive string, args []string) error {
	switch directive {
	case "port":
		if len(args) != 1 {
			return fmt.Errorf("port requires exactly one argument")
		}
		port, err := strconv.Atoi(args[0])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port number: %s", args[0])
		}
		c.Port = port

	case "listenaddress":
		if len(args) != 1 {
			return fmt.Errorf("listenaddress requires exactly one argument")
		}
		c.ListenAddress = append(c.ListenAddress, args[0])

	case "hostkey":
		if len(args) != 1 {
			return fmt.Errorf("hostkey requires exactly one argument")
		}
		// If this is the first HostKey directive, clear the defaults
		if len(c.HostKey) == 3 &&
			c.HostKey[0] == "/etc/ssh/ssh_host_rsa_key" &&
			c.HostKey[1] == "/etc/ssh/ssh_host_ecdsa_key" &&
			c.HostKey[2] == "/etc/ssh/ssh_host_ed25519_key" {
			c.HostKey = []string{}
		}
		c.HostKey = append(c.HostKey, args[0])

	case "passwordauthentication":
		if len(args) != 1 {
			return fmt.Errorf("passwordauthentication requires exactly one argument")
		}
		c.PasswordAuthentication = parseBool(args[0])

	case "pubkeyauthentication":
		if len(args) != 1 {
			return fmt.Errorf("pubkeyauthentication requires exactly one argument")
		}
		c.PubkeyAuthentication = parseBool(args[0])

	case "kbdinteractiveauthentication":
		if len(args) != 1 {
			return fmt.Errorf("kbdinteractiveauthentication requires exactly one argument")
		}
		c.KbdInteractiveAuthentication = parseBool(args[0])

	case "subsystem":
		if len(args) != 2 {
			return fmt.Errorf("subsystem requires exactly two arguments")
		}
		c.Subsystem[args[0]] = args[1]

	case "allowagentforwarding":
		if len(args) != 1 {
			return fmt.Errorf("allowagentforwarding requires exactly one argument")
		}
		c.AllowAgentForwarding = parseBool(args[0])

	case "allowtcpforwarding":
		if len(args) != 1 {
			return fmt.Errorf("allowtcpforwarding requires exactly one argument")
		}
		c.AllowTcpForwarding = parseBool(args[0])

	case "x11forwarding":
		if len(args) != 1 {
			return fmt.Errorf("x11forwarding requires exactly one argument")
		}
		c.X11Forwarding = parseBool(args[0])

	case "x11displayoffset":
		if len(args) != 1 {
			return fmt.Errorf("x11displayoffset requires exactly one argument")
		}
		offset, err := strconv.Atoi(args[0])
		if err != nil || offset < 0 {
			return fmt.Errorf("invalid x11displayoffset value: %s", args[0])
		}
		c.X11DisplayOffset = offset

	case "x11uselocalhost":
		if len(args) != 1 {
			return fmt.Errorf("x11uselocalhost requires exactly one argument")
		}
		c.X11UseLocalhost = parseBool(args[0])

	case "gatewayports":
		if len(args) != 1 {
			return fmt.Errorf("gatewayports requires exactly one argument")
		}
		c.GatewayPorts = parseBool(args[0])

	case "permitrootlogin":
		if len(args) != 1 {
			return fmt.Errorf("permitrootlogin requires exactly one argument")
		}
		value := strings.ToLower(args[0])
		if value != "yes" && value != "no" && value != "prohibit-password" && value != "forced-commands-only" {
			return fmt.Errorf("invalid permitrootlogin value: %s", args[0])
		}
		c.PermitRootLogin = value

	case "allowusers":
		if len(args) == 0 {
			return fmt.Errorf("allowusers requires at least one argument")
		}
		c.AllowUsers = append(c.AllowUsers, args...)

	case "denyusers":
		if len(args) == 0 {
			return fmt.Errorf("denyusers requires at least one argument")
		}
		c.DenyUsers = append(c.DenyUsers, args...)

	case "authorizedkeysfile":
		if len(args) == 0 {
			return fmt.Errorf("authorizedkeysfile requires at least one argument")
		}
		c.AuthorizedKeysFile = args

	case "trustedusercakeys":
		if len(args) != 1 {
			return fmt.Errorf("trustedusercakeys requires exactly one argument")
		}
		c.TrustedUserCAKeys = append(c.TrustedUserCAKeys, args[0])

	case "revokedkeys":
		if len(args) != 1 {
			return fmt.Errorf("revokedkeys requires exactly one argument")
		}
		c.RevokedKeys = append(c.RevokedKeys, args[0])

	case "loglevel":
		if len(args) != 1 {
			return fmt.Errorf("loglevel requires exactly one argument")
		}
		level := strings.ToUpper(args[0])
		if !isValidLogLevel(level) {
			return fmt.Errorf("invalid log level: %s", args[0])
		}
		c.LogLevel = level

	case "syslogfacility":
		if len(args) != 1 {
			return fmt.Errorf("syslogfacility requires exactly one argument")
		}
		facility := strings.ToUpper(args[0])
		if !isValidSyslogFacility(facility) {
			return fmt.Errorf("invalid syslog facility: %s", args[0])
		}
		c.SyslogFacility = facility

	case "logfile":
		if len(args) != 1 {
			return fmt.Errorf("logfile requires exactly one argument")
		}
		c.LogFile = args[0]

	case "metricsenabled":
		if len(args) != 1 {
			return fmt.Errorf("metricsenabled requires exactly one argument")
		}
		c.MetricsEnabled = parseBool(args[0])

	case "metricsaddress":
		if len(args) != 1 {
			return fmt.Errorf("metricsaddress requires exactly one argument")
		}
		// Validate address format (host:port)
		if _, _, err := net.SplitHostPort(args[0]); err != nil {
			return fmt.Errorf("invalid metricsaddress format: %s (expected host:port)", args[0])
		}
		c.MetricsAddress = args[0]

		// Add more directives as needed - keeping minimal for now
	}

	return nil
}

// parseBool converts OpenSSH boolean values to Go bool.
// OpenSSH accepts yes/no, true/false, 1/0 as boolean values.
func parseBool(value string) bool {
	switch strings.ToLower(value) {
	case "yes", "true", "1":
		return true
	default:
		return false
	}
}

// isValidLogLevel validates OpenSSH log levels.
// OpenSSH supports: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, DEBUG3
func isValidLogLevel(level string) bool {
	validLevels := []string{
		"QUIET", "FATAL", "ERROR", "INFO", "VERBOSE",
		"DEBUG", "DEBUG1", "DEBUG2", "DEBUG3",
	}
	for _, valid := range validLevels {
		if level == valid {
			return true
		}
	}
	return false
}

// isValidSyslogFacility validates OpenSSH syslog facilities.
// OpenSSH supports standard syslog facilities
func isValidSyslogFacility(facility string) bool {
	validFacilities := []string{
		"DAEMON", "USER", "AUTH", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3",
		"LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7", "AUTHPRIV",
	}
	for _, valid := range validFacilities {
		if facility == valid {
			return true
		}
	}
	return false
}
