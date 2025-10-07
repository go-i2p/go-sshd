// Package config provides OpenSSH-compatible configuration parsing.
// This package wraps google/shlex and other libraries to parse sshd_config
// files with full OpenSSH compatibility.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

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
	PasswordAuthentication bool     `json:"password_authentication"`
	PubkeyAuthentication   bool     `json:"pubkey_authentication"`
	AuthorizedKeysFile     []string `json:"authorized_keys_file"`

	// Session settings
	PermitRootLogin string   `json:"permit_root_login"`
	AllowUsers      []string `json:"allow_users"`
	DenyUsers       []string `json:"deny_users"`

	// Feature settings
	Subsystem          map[string]string `json:"subsystem"`
	AllowTcpForwarding bool              `json:"allow_tcp_forwarding"`
	X11Forwarding      bool              `json:"x11_forwarding"`
	GatewayPorts       bool              `json:"gateway_ports"`
}

// Load reads and parses an OpenSSH sshd_config file.
// This function uses google/shlex for shell-style tokenization
// to maintain full compatibility with OpenSSH config parsing.
func Load(filename string) (*Config, error) {
	// Set defaults matching OpenSSH behavior
	cfg := &Config{
		Port:                   22,
		ListenAddress:          []string{"0.0.0.0"},
		Protocol:               []int{2},
		HostKey:                []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"},
		PasswordAuthentication: true,
		PubkeyAuthentication:   true,
		AuthorizedKeysFile:     []string{".ssh/authorized_keys"},
		PermitRootLogin:        "prohibit-password",
		Subsystem:              make(map[string]string),
		AllowTcpForwarding:     true,
		X11Forwarding:          false,
		GatewayPorts:           false,
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

	case "subsystem":
		if len(args) != 2 {
			return fmt.Errorf("subsystem requires exactly two arguments")
		}
		c.Subsystem[args[0]] = args[1]

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
