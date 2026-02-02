// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This file implements user authorization logic including user filtering and root login restrictions.
package handlers

import (
	"fmt"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// AuthorizedKeyOptions represents parsed options from an authorized_keys entry.
// Based on OpenSSH authorized_keys format: options,options... keytype base64key comment
type AuthorizedKeyOptions struct {
	// Command restriction - if set, only this command can be executed
	Command string
	// Environment variables to set for the session
	Environment map[string]string
	// Restrict source addresses
	From []string
	// Disable features
	NoPortForwarding  bool
	NoPTY             bool
	NoUserRC          bool
	NoX11Forwarding   bool
	NoAgentForwarding bool
	// Force PTY allocation
	PTY bool
	// Restrict to specific SSH client versions
	RestrictAuth []string
}

// UserAuthorizer handles user-level authorization decisions.
// This wraps the configuration-based authorization rules.
type UserAuthorizer struct {
	config *config.Config
	logger *logrus.Logger
}

// NewUserAuthorizer creates a new user authorization handler.
func NewUserAuthorizer(cfg *config.Config, logger *logrus.Logger) *UserAuthorizer {
	return &UserAuthorizer{
		config: cfg,
		logger: logger,
	}
}

// IsUserAllowed checks if a user is allowed to connect based on AllowUsers and DenyUsers.
// Follows OpenSSH precedence: DenyUsers is checked first, then AllowUsers.
// Patterns support wildcards (* and ?) and user@host format.
func (ua *UserAuthorizer) IsUserAllowed(username, remoteAddr string) bool {
	host := extractHostFromAddr(remoteAddr)

	if ua.isDeniedByDenyUsers(username, host) {
		return false
	}

	return ua.isAllowedByAllowUsers(username, host)
}

// extractHostFromAddr extracts the hostname or IP from a remote address, removing the port.
func extractHostFromAddr(remoteAddr string) string {
	if !strings.Contains(remoteAddr, ":") {
		return remoteAddr
	}

	parts := strings.Split(remoteAddr, ":")
	if len(parts) >= 2 {
		return strings.Join(parts[:len(parts)-1], ":")
	}
	return remoteAddr
}

// isDeniedByDenyUsers checks if the user matches any DenyUsers patterns.
func (ua *UserAuthorizer) isDeniedByDenyUsers(username, host string) bool {
	for _, pattern := range ua.config.DenyUsers {
		if ua.matchUserPattern(pattern, username, host) {
			ua.logger.Infof("User %s denied by DenyUsers pattern: %s", username, pattern)
			return true
		}
	}
	return false
}

// isAllowedByAllowUsers checks if the user matches AllowUsers patterns.
func (ua *UserAuthorizer) isAllowedByAllowUsers(username, host string) bool {
	if len(ua.config.AllowUsers) == 0 {
		return true
	}

	for _, pattern := range ua.config.AllowUsers {
		if ua.matchUserPattern(pattern, username, host) {
			ua.logger.Debugf("User %s allowed by AllowUsers pattern: %s", username, pattern)
			return true
		}
	}

	ua.logger.Infof("User %s not in AllowUsers list", username)
	return false
}

// IsRootLoginAllowed checks if root login is permitted based on PermitRootLogin setting.
// Options: yes, no, prohibit-password, forced-commands-only
func (ua *UserAuthorizer) IsRootLoginAllowed(username, authMethod string) bool {
	if username != "root" {
		return true // Not root, allow
	}

	switch ua.config.PermitRootLogin {
	case "yes":
		return true
	case "no":
		ua.logger.Infof("Root login denied by PermitRootLogin=no")
		return false
	case "prohibit-password":
		// Allow only public key authentication for root
		// Block password and keyboard-interactive (which can do password prompts)
		if authMethod == "password" || authMethod == "keyboard-interactive" {
			ua.logger.Infof("Root %s login denied by PermitRootLogin=prohibit-password", authMethod)
			return false
		}
		return true
	case "forced-commands-only":
		// Block password and keyboard-interactive auth for root
		// For public key auth, will need secondary check after key validation
		// to verify the key has a command= option (done in auth.go)
		if authMethod == "password" || authMethod == "keyboard-interactive" {
			ua.logger.Infof("Root %s login denied by PermitRootLogin=forced-commands-only", authMethod)
			return false
		}
		// For publickey, this check passes but key must have command= option
		// (verified after key validation in auth handler)
		return true
	default:
		// Unknown value, default to prohibit-password for security
		ua.logger.Warnf("Unknown PermitRootLogin value: %s, defaulting to prohibit-password", ua.config.PermitRootLogin)
		if authMethod == "password" || authMethod == "keyboard-interactive" {
			return false
		}
		return true
	}
}

// IsRootForcedCommandsRequired returns true if root login is set to forced-commands-only.
// When true, root login via public key must have a command= restriction in authorized_keys.
// This should be called after successful key validation to verify the key has a forced command.
func (ua *UserAuthorizer) IsRootForcedCommandsRequired(username string) bool {
	if username != "root" {
		return false // Not root, no restriction
	}
	return ua.config.PermitRootLogin == "forced-commands-only"
}

// IsGroupAllowed checks if a user is allowed to connect based on AllowGroups and DenyGroups.
// Follows OpenSSH precedence: DenyGroups is checked first, then AllowGroups.
// Uses os/user package to look up the user's group memberships from the system.
func (ua *UserAuthorizer) IsGroupAllowed(username string) bool {
	userGroups, err := ua.getUserGroups(username)
	if err != nil {
		return ua.handleGroupLookupError(username, err)
	}

	if ua.isUserInDenyGroups(username, userGroups) {
		return false
	}

	return ua.isUserInAllowGroups(username, userGroups)
}

// handleGroupLookupError handles errors during group lookup.
func (ua *UserAuthorizer) handleGroupLookupError(username string, err error) bool {
	ua.logger.Warnf("Failed to get groups for user %s: %v", username, err)

	// If groups are configured, deny for safety
	if len(ua.config.AllowGroups) > 0 || len(ua.config.DenyGroups) > 0 {
		ua.logger.Infof("Denying user %s due to group lookup failure with group restrictions configured", username)
		return false
	}

	// No group restrictions configured, allow
	return true
}

// isUserInDenyGroups checks if user belongs to any denied group.
func (ua *UserAuthorizer) isUserInDenyGroups(username string, userGroups []string) bool {
	for _, denyPattern := range ua.config.DenyGroups {
		for _, userGroup := range userGroups {
			if ua.matchWildcard(denyPattern, userGroup) {
				ua.logger.Infof("User %s denied by DenyGroups pattern: %s (member of %s)", username, denyPattern, userGroup)
				return true
			}
		}
	}
	return false
}

// isUserInAllowGroups checks if user belongs to any allowed group.
func (ua *UserAuthorizer) isUserInAllowGroups(username string, userGroups []string) bool {
	// If no AllowGroups specified, user is allowed
	if len(ua.config.AllowGroups) == 0 {
		return true
	}

	for _, allowPattern := range ua.config.AllowGroups {
		for _, userGroup := range userGroups {
			if ua.matchWildcard(allowPattern, userGroup) {
				ua.logger.Debugf("User %s allowed by AllowGroups pattern: %s (member of %s)", username, allowPattern, userGroup)
				return true
			}
		}
	}

	ua.logger.Infof("User %s not in any AllowGroups", username)
	return false
}

// getUserGroups returns the list of group names that a user belongs to.
// Uses the os/user package for portable group lookups.
func (ua *UserAuthorizer) getUserGroups(username string) ([]string, error) {
	// Look up the user
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("user lookup failed: %w", err)
	}

	// Get the user's group IDs
	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("group lookup failed: %w", err)
	}

	// Convert group IDs to group names
	var groupNames []string
	for _, gid := range groupIDs {
		grp, err := user.LookupGroupId(gid)
		if err != nil {
			// Log but continue - some system groups may not resolve
			ua.logger.Debugf("Could not resolve group ID %s: %v", gid, err)
			continue
		}
		groupNames = append(groupNames, grp.Name)
	}

	return groupNames, nil
}

// matchUserPattern matches a user against a pattern supporting wildcards and user@host format.
// Pattern format: user, user@host, @host, or wildcards with * and ?
func (ua *UserAuthorizer) matchUserPattern(pattern, username, host string) bool {
	// Handle @host pattern (any user from this host) - must check before @ contains check
	if strings.HasPrefix(pattern, "@") {
		hostPattern := pattern[1:]
		return ua.matchWildcard(hostPattern, host)
	}

	// Handle user@host pattern
	if strings.Contains(pattern, "@") {
		parts := strings.SplitN(pattern, "@", 2)
		userPattern := parts[0]
		hostPattern := parts[1]

		// Match both user and host
		userMatch := ua.matchWildcard(userPattern, username)
		hostMatch := ua.matchWildcard(hostPattern, host)
		return userMatch && hostMatch
	}

	// Plain username pattern
	return ua.matchWildcard(pattern, username)
}

// matchWildcard performs wildcard matching with * and ? support.
// Uses filepath.Match for consistent behavior with shell patterns.
func (ua *UserAuthorizer) matchWildcard(pattern, str string) bool {
	matched, err := filepath.Match(pattern, str)
	if err != nil {
		ua.logger.Debugf("Invalid pattern %s: %v", pattern, err)
		return false
	}
	return matched
}

// ParseAuthorizedKeyOptions parses options from an authorized_keys line.
// Format: option1,option2=value,option3="quoted value" keytype base64key comment
// Returns the key part (without options) and parsed options.
func ParseAuthorizedKeyOptions(line string) (string, *AuthorizedKeyOptions, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, fmt.Errorf("empty or comment line")
	}

	// Check if line starts with an option (contains = or known option names before space)
	// Simple heuristic: if the first part contains '=' or matches known options, it's an option list
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return line, &AuthorizedKeyOptions{}, nil // No options, return as-is
	}

	firstPart := parts[0]
	hasOptions := strings.Contains(firstPart, "=") ||
		strings.Contains(firstPart, "command") ||
		strings.Contains(firstPart, "no-port-forwarding") ||
		strings.Contains(firstPart, "no-pty") ||
		strings.Contains(firstPart, "no-user-rc") ||
		strings.Contains(firstPart, "no-X11-forwarding") ||
		strings.Contains(firstPart, "no-agent-forwarding") ||
		strings.Contains(firstPart, "pty") ||
		strings.Contains(firstPart, "from")

	if !hasOptions {
		// No options present
		return line, &AuthorizedKeyOptions{}, nil
	}

	// Find where options end and key begins
	// Look for the key type (ssh-rsa, ssh-dss, ecdsa-sha2-*, ssh-ed25519)
	keyTypePattern := regexp.MustCompile(`\b(ssh-rsa|ssh-dss|ecdsa-sha2-\w+|ssh-ed25519)\b`)
	keyStart := keyTypePattern.FindStringIndex(line)
	if keyStart == nil {
		return "", nil, fmt.Errorf("no valid key type found")
	}

	optionsPart := strings.TrimSpace(line[:keyStart[0]])
	keyPart := strings.TrimSpace(line[keyStart[0]:])

	// Parse options
	options, err := parseOptionsList(optionsPart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse options: %w", err)
	}

	return keyPart, options, nil
}

// parseOptionsList parses a comma-separated list of options.
// Handles quoted values and key=value pairs.
func parseOptionsList(optionsPart string) (*AuthorizedKeyOptions, error) {
	options := &AuthorizedKeyOptions{
		Environment: make(map[string]string),
	}

	if optionsPart == "" {
		return options, nil
	}

	// Split on commas, but respect quoted strings
	optionList := parseCommaSeparated(optionsPart)

	for _, opt := range optionList {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}

		// Parse individual option
		if err := parseOption(opt, options); err != nil {
			return nil, fmt.Errorf("invalid option %q: %w", opt, err)
		}
	}

	return options, nil
}

// parseCommaSeparated splits a string on commas while respecting quoted strings.
func parseCommaSeparated(s string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				result = append(result, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// parseOption parses a single option and updates the options struct.
func parseOption(opt string, options *AuthorizedKeyOptions) error {
	// Handle key=value options
	if strings.Contains(opt, "=") {
		parts := strings.SplitN(opt, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		switch key {
		case "command":
			options.Command = value
		case "environment":
			// Format: environment="VAR=value"
			if envParts := strings.SplitN(value, "=", 2); len(envParts) == 2 {
				options.Environment[envParts[0]] = envParts[1]
			}
		case "from":
			// Format: from="host1,host2"
			hosts := strings.Split(value, ",")
			for _, host := range hosts {
				options.From = append(options.From, strings.TrimSpace(host))
			}
		default:
			// Unknown key=value option, ignore for compatibility
		}
	} else {
		// Handle flag options
		switch opt {
		case "no-port-forwarding":
			options.NoPortForwarding = true
		case "no-pty":
			options.NoPTY = true
		case "no-user-rc":
			options.NoUserRC = true
		case "no-X11-forwarding":
			options.NoX11Forwarding = true
		case "no-agent-forwarding":
			options.NoAgentForwarding = true
		case "pty":
			options.PTY = true
		default:
			// Unknown flag option, ignore for compatibility
		}
	}

	return nil
}
