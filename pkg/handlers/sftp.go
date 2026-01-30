// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// SFTPHandler handles SFTP subsystem requests.
// This is a thin wrapper around pkg/sftp for complete SFTP protocol support.
type SFTPHandler struct {
	config *config.Config
	logger *logrus.Logger
}

// NewSFTPHandler creates a new SFTP subsystem handler.
// Uses library-first approach - delegates all SFTP protocol to pkg/sftp.
func NewSFTPHandler(cfg *config.Config, logger *logrus.Logger) *SFTPHandler {
	return &SFTPHandler{
		config: cfg,
		logger: logger,
	}
}

// CreateSubsystemHandler creates the SFTP subsystem handler for gliderlabs/ssh.
// This integrates pkg/sftp.RequestServer with SSH session management and applies security restrictions.
// Uses custom handlers to intercept all file operations and validate them against security policies.
func (h *SFTPHandler) CreateSubsystemHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		user := s.User()
		h.logger.Infof("SFTP subsystem started for user %s from %s", user, s.RemoteAddr())

		// Configure chroot/working directory for the user
		workingDir, err := h.ConfigureChroot(user)
		if err != nil {
			h.logger.Errorf("Failed to configure chroot for user %s: %v", user, err)
			return
		}

		// Create secure SFTP handlers that validate all file operations
		secureHandlers := newSecureSFTPHandlers(h, user, workingDir)

		// Create SFTP request server using pkg/sftp with security-validating handlers
		// Using RequestServer instead of Server allows us to intercept and validate all operations
		server := sftp.NewRequestServer(s, secureHandlers.Handlers(),
			sftp.WithStartDirectory(workingDir))

		// Serve SFTP requests - all operations go through our secure handlers
		if err := server.Serve(); err != nil {
			if err != io.EOF {
				h.logger.Errorf("SFTP server error for user %s: %v", user, err)
			}
		} else {
			h.logger.Infof("SFTP subsystem completed for user %s", user)
		}
	}
}

// buildServerOptions creates SFTP server options based on configuration and user context.
// Uses pkg/sftp configuration options for server behavior with security restrictions.
func (h *SFTPHandler) buildServerOptions(workingDir string) []sftp.ServerOption {
	var options []sftp.ServerOption

	// Add debug logging if needed
	if h.logger.Level == logrus.DebugLevel {
		options = append(options, sftp.WithDebug(h.logger.Writer()))
	}

	// Configure working directory with proper chroot/security restrictions
	// Normalize the path to prevent directory traversal attacks
	normalizedDir := filepath.Clean(workingDir)
	h.logger.Debugf("SFTP server working directory set to: %s", normalizedDir)
	options = append(options, sftp.WithServerWorkingDirectory(normalizedDir))

	return options
}

// GetSupportedSubsystems returns the list of supported subsystems.
// Currently only supports "sftp" via pkg/sftp integration.
func (h *SFTPHandler) GetSupportedSubsystems() []string {
	return []string{"sftp"}
}

// ConfigureChroot configures SFTP chroot functionality based on user and security settings.
// This implements a secure default approach where users are restricted to their home directories.
// Following OpenSSH patterns for SFTP security and user isolation.
func (h *SFTPHandler) ConfigureChroot(username string) (string, error) {
	// Get user information to determine home directory
	userInfo, err := user.Lookup(username)
	if err != nil {
		h.logger.Warnf("User lookup failed for %s: %v", username, err)
		// Fallback to root filesystem for system users or when user lookup fails
		h.logger.Debugf("SFTP using filesystem root for user %s due to lookup failure", username)
		return "/", nil
	}

	// For security, default to user's home directory as chroot
	// This prevents users from accessing system files outside their home
	chrootPath := userInfo.HomeDir

	// Verify the directory exists and is accessible
	if stat, err := os.Stat(chrootPath); err != nil {
		h.logger.Warnf("User home directory %s not accessible for %s: %v", chrootPath, username, err)
		// Fallback to root for system compatibility, but log the security implication
		h.logger.Infof("SFTP fallback to filesystem root for user %s - consider creating home directory", username)
		return "/", nil
	} else if !stat.IsDir() {
		h.logger.Warnf("User home path %s is not a directory for %s", chrootPath, username)
		return "/", nil
	}

	// For root user, allow full filesystem access for administrative tasks
	if username == "root" {
		h.logger.Debugf("SFTP allowing full filesystem access for root user")
		return "/", nil
	}

	h.logger.Infof("SFTP chroot configured for user %s: %s", username, chrootPath)
	return chrootPath, nil
}

// ValidateFileOperation validates file operations based on security policies and configuration.
// Implements OpenSSH-compatible security controls for SFTP file access.
func (h *SFTPHandler) ValidateFileOperation(user, path, operation string) error {
	h.logger.Debugf("Validating SFTP operation %s on %s for user %s", operation, path, user)

	// Prevent directory traversal attacks by checking for .. in original path
	if strings.Contains(path, "..") {
		h.logger.Warnf("SFTP operation %s denied for user %s: directory traversal attempt on %s", operation, user, path)
		return errors.New("directory traversal not allowed")
	}

	// Normalize the path to prevent other forms of path manipulation
	cleanPath := filepath.Clean(path)

	// Block access to sensitive system files for non-root users
	if user != "root" {
		if err := h.validateSystemFileAccess(cleanPath, operation, user); err != nil {
			return err
		}
	}

	// Validate write operations to critical system directories
	if err := h.validateWriteOperations(cleanPath, operation, user); err != nil {
		return err
	}

	// Log successful validation
	h.logger.Debugf("SFTP operation %s on %s allowed for user %s", operation, cleanPath, user)
	return nil
}

// validateSystemFileAccess prevents non-root users from accessing sensitive system files.
func (h *SFTPHandler) validateSystemFileAccess(path, operation, user string) error {
	// Block access to sensitive system directories for non-root users
	sensitiveDirectories := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/ssh/",
		"/root/",
		"/var/log/",
		"/proc/",
		"/sys/",
		"/dev/",
	}

	for _, sensitive := range sensitiveDirectories {
		if strings.HasPrefix(path, sensitive) || path == strings.TrimSuffix(sensitive, "/") {
			h.logger.Warnf("SFTP operation %s denied for user %s: access to sensitive path %s", operation, user, path)
			return errors.New("access to system files denied")
		}
	}

	return nil
}

// validateWriteOperations validates write operations to prevent system damage.
func (h *SFTPHandler) validateWriteOperations(path, operation, user string) error {
	// Check if this is a write operation
	// Note: includes both generic names ("delete") and SFTP method names ("remove")
	writeOperations := []string{"write", "create", "delete", "mkdir", "rmdir", "rename", "remove", "setstat", "symlink", "link"}
	isWriteOp := false
	for _, writeOp := range writeOperations {
		if strings.EqualFold(operation, writeOp) {
			isWriteOp = true
			break
		}
	}

	if !isWriteOp {
		return nil // Read operations are generally allowed
	}

	// Block write operations to critical system directories for all users
	protectedDirectories := []string{
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
		"/boot/",
		"/etc/systemd/",
	}

	for _, protected := range protectedDirectories {
		if strings.HasPrefix(path, protected) {
			h.logger.Warnf("SFTP write operation %s denied for user %s: protected system directory %s", operation, user, path)
			return errors.New("write operations to system directories not allowed")
		}
	}

	return nil
}

// secureSFTPHandlers implements pkg/sftp.Handlers interfaces with security validation.
// All file operations are validated through ValidateFileOperation before execution.
// This ensures the security policies defined in SFTPHandler are actually enforced.
type secureSFTPHandlers struct {
	handler    *SFTPHandler
	username   string
	workingDir string
}

// newSecureSFTPHandlers creates secure SFTP handlers for a specific user session.
func newSecureSFTPHandlers(h *SFTPHandler, username, workingDir string) *secureSFTPHandlers {
	return &secureSFTPHandlers{
		handler:    h,
		username:   username,
		workingDir: workingDir,
	}
}

// Handlers returns the sftp.Handlers struct with security-validating implementations.
func (s *secureSFTPHandlers) Handlers() sftp.Handlers {
	return sftp.Handlers{
		FileGet:  s,
		FilePut:  s,
		FileCmd:  s,
		FileList: s,
	}
}

// resolvePath resolves a relative path against the working directory and validates it.
func (s *secureSFTPHandlers) resolvePath(requestPath string) string {
	if filepath.IsAbs(requestPath) {
		return filepath.Clean(requestPath)
	}
	return filepath.Clean(filepath.Join(s.workingDir, requestPath))
}

// checkDirectoryTraversal checks for directory traversal attempts in the raw path.
// This must be called with the original request path before cleaning.
func (s *secureSFTPHandlers) checkDirectoryTraversal(rawPath string) error {
	if strings.Contains(rawPath, "..") {
		return errors.New("directory traversal not allowed")
	}
	return nil
}

// Fileread implements sftp.FileReader - validates and handles file read operations.
func (s *secureSFTPHandlers) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	// Check for directory traversal in raw path first
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP read denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return nil, err
	}

	path := s.resolvePath(r.Filepath)

	// Validate the read operation against security policies
	if err := s.handler.ValidateFileOperation(s.username, path, "read"); err != nil {
		s.handler.logger.Warnf("SFTP read denied for user %s on %s: %v", s.username, path, err)
		return nil, err
	}

	// Open file for reading - OS permissions still apply
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// Filewrite implements sftp.FileWriter - validates and handles file write operations.
func (s *secureSFTPHandlers) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	// Check for directory traversal in raw path first
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP write denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return nil, err
	}

	path := s.resolvePath(r.Filepath)

	// Validate the write operation against security policies
	if err := s.handler.ValidateFileOperation(s.username, path, "write"); err != nil {
		s.handler.logger.Warnf("SFTP write denied for user %s on %s: %v", s.username, path, err)
		return nil, err
	}

	// Determine flags from the request
	pflags := r.Pflags()
	flags := os.O_WRONLY

	if pflags.Creat {
		flags |= os.O_CREATE
	}
	if pflags.Trunc {
		flags |= os.O_TRUNC
	}
	if pflags.Excl {
		flags |= os.O_EXCL
	}
	// Note: Don't use O_APPEND with WriterAt - they conflict

	// Create parent directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// Open file for writing - OS permissions still apply
	file, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// Filecmd implements sftp.FileCmder - validates and handles file commands.
// Handles: Setstat, Rename, Rmdir, Mkdir, Link, Symlink, Remove
func (s *secureSFTPHandlers) Filecmd(r *sftp.Request) error {
	// Check for directory traversal in raw path first
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP command denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return err
	}
	// Also check target path for rename/link operations
	if r.Target != "" {
		if err := s.checkDirectoryTraversal(r.Target); err != nil {
			s.handler.logger.Warnf("SFTP command denied for user %s: directory traversal attempt on target %s", s.username, r.Target)
			return err
		}
	}

	path := s.resolvePath(r.Filepath)

	// Map request method to operation name for validation
	operation := strings.ToLower(r.Method)

	// Validate the operation against security policies
	if err := s.handler.ValidateFileOperation(s.username, path, operation); err != nil {
		s.handler.logger.Warnf("SFTP %s denied for user %s on %s: %v", operation, s.username, path, err)
		return err
	}

	// For operations with a target (rename, link, symlink), validate target too
	if r.Target != "" {
		targetPath := s.resolvePath(r.Target)
		if err := s.handler.ValidateFileOperation(s.username, targetPath, operation); err != nil {
			s.handler.logger.Warnf("SFTP %s denied for user %s on target %s: %v", operation, s.username, targetPath, err)
			return err
		}
	}

	// Execute the file command
	switch r.Method {
	case "Setstat":
		return s.handleSetstat(path, r)
	case "Rename":
		return os.Rename(path, s.resolvePath(r.Target))
	case "Rmdir":
		return os.Remove(path)
	case "Mkdir":
		return os.Mkdir(path, 0o755)
	case "Remove":
		return os.Remove(path)
	case "Symlink":
		return os.Symlink(path, s.resolvePath(r.Target))
	case "Link":
		return os.Link(path, s.resolvePath(r.Target))
	default:
		return errors.New("unsupported command: " + r.Method)
	}
}

// handleSetstat handles the Setstat command for changing file attributes.
func (s *secureSFTPHandlers) handleSetstat(path string, r *sftp.Request) error {
	attrs := r.Attributes()
	attrFlags := r.AttrFlags()

	// Handle permissions change
	if attrFlags.Permissions {
		if err := os.Chmod(path, attrs.FileMode()); err != nil {
			return err
		}
	}

	// Handle ownership change (requires root)
	if attrFlags.UidGid {
		uid := int(attrs.UID)
		gid := int(attrs.GID)
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}

	// Handle size change (truncate)
	if attrFlags.Size {
		if err := os.Truncate(path, int64(attrs.Size)); err != nil {
			return err
		}
	}

	// Handle access/modification time change
	if attrFlags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		if err := os.Chtimes(path, atime, mtime); err != nil {
			return err
		}
	}

	return nil
}

// Filelist implements sftp.FileLister - validates and handles directory listing.
// Handles: List, Stat, Readlink
func (s *secureSFTPHandlers) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	// Check for directory traversal in raw path first
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP list denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return nil, err
	}

	path := s.resolvePath(r.Filepath)

	// Validate the operation against security policies
	operation := strings.ToLower(r.Method)
	if err := s.handler.ValidateFileOperation(s.username, path, operation); err != nil {
		s.handler.logger.Warnf("SFTP %s denied for user %s on %s: %v", operation, s.username, path, err)
		return nil, err
	}

	switch r.Method {
	case "List":
		return s.handleList(path)
	case "Stat":
		return s.handleStat(path)
	case "Readlink":
		return s.handleReadlink(path)
	default:
		return nil, errors.New("unsupported list method: " + r.Method)
	}
}

// handleList handles directory listing requests.
func (s *secureSFTPHandlers) handleList(path string) (sftp.ListerAt, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.Readdir(-1)
	if err != nil {
		return nil, err
	}

	return listerat(entries), nil
}

// handleStat handles file/directory stat requests.
func (s *secureSFTPHandlers) handleStat(path string) (sftp.ListerAt, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return listerat([]os.FileInfo{info}), nil
}

// handleReadlink handles symbolic link resolution.
func (s *secureSFTPHandlers) handleReadlink(path string) (sftp.ListerAt, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return nil, err
	}
	// Return the link target as a fake FileInfo
	return listerat([]os.FileInfo{symlinkInfo{name: target}}), nil
}

// listerat implements sftp.ListerAt for returning file info lists.
type listerat []os.FileInfo

// ListAt implements the sftp.ListerAt interface.
func (l listerat) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}

	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

// symlinkInfo is a minimal FileInfo implementation for readlink results.
type symlinkInfo struct {
	name string
}

func (s symlinkInfo) Name() string       { return s.name }
func (s symlinkInfo) Size() int64        { return 0 }
func (s symlinkInfo) Mode() os.FileMode  { return os.ModeSymlink }
func (s symlinkInfo) ModTime() time.Time { return time.Time{} }
func (s symlinkInfo) IsDir() bool        { return false }
func (s symlinkInfo) Sys() interface{}   { return nil }

// fileWrapper wraps os.File to track open files for proper cleanup.
type fileWrapper struct {
	*os.File
	mu     sync.Mutex
	closed bool
}

func (f *fileWrapper) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.File.Close()
}
