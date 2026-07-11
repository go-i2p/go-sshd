// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"errors"
	"fmt"
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
		// Note: WithDebug is not available for RequestServer; debug logging would require
		// switching to pkg/sftp.Server, which would lose our custom security handler integration
		server := sftp.NewRequestServer(s, secureHandlers.Handlers(),
			sftp.WithStartDirectory(workingDir))

		// Serve SFTP requests - all operations go through our secure handlers.
		// Drop the daemon's own privileges (normally root) to the
		// authenticated user for the whole session, so file operations are
		// subject to the real filesystem permission checks for that user
		// rather than bypassing them as root. When the daemon is not
		// running as root, this is a no-op.
		err = h.serveWithUserPrivileges(user, server.Serve)
		if err != nil {
			if err != io.EOF {
				h.logger.Errorf("SFTP server error for user %s: %v", user, err)
			}
		} else {
			h.logger.Infof("SFTP subsystem completed for user %s", user)
		}
	}
}

// serveWithUserPrivileges resolves username's credential and runs serve
// under that user's privileges via withDroppedPrivileges. If the daemon is
// not running as root, or the user cannot be resolved, serve still runs
// but under the daemon's own identity (matching prior behavior) - the
// latter is logged since it means chroot/permission confinement is the
// only remaining protection for that session.
func (h *SFTPHandler) serveWithUserPrivileges(username string, serve func() error) error {
	if !canDropPrivileges() {
		return serve()
	}

	cred, err := lookupUserCredential(username)
	if err != nil {
		h.logger.Warnf("Cannot resolve credential for SFTP user %s, serving as daemon identity: %v", username, err)
		return serve()
	}

	return withDroppedPrivileges(cred, serve)
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

// ConfigureChroot configures SFTP root directory (working directory) based on user and security settings.
// This implements a lexical-path-based confinement where users are restricted to a root directory
// via pathname checking (not an OS-level chroot/mount namespace).
// Note: Confinement is "lexical" (string path prefix checking) and can theoretically be escaped
// via pre-existing symlinks on the filesystem. This is mitigated by:
// 1) resolvePath() using filepath.EvalSymlinks to detect symlink escapes at decision time
// 2) serveWithUserPrivileges() dropping privileges to the authenticated user (when running as root)
// 3) OS permission checks re-applied at the syscall level by the authenticated user's credentials
// For truly isolated environments (non-root deployments), use OS-level confinement mechanisms
// (e.g. mount namespaces, containerization).
// Priority: 1) Configured SFTPRootDir 2) User home directory 3) Fallback to /
func (h *SFTPHandler) ConfigureChroot(username string) (string, error) {
	// Try configured root directory first
	if path, ok := h.tryConfiguredRootDir(username); ok {
		return path, nil
	}

	// Root user gets full access
	if username == "root" {
		h.logger.Debugf("SFTP allowing full filesystem access for root user")
		return "/", nil
	}

	// Try user home directory
	return h.getUserHomeChroot(username)
}

// tryConfiguredRootDir attempts to use the configured SFTP root directory.
func (h *SFTPHandler) tryConfiguredRootDir(username string) (string, bool) {
	if h.config == nil || h.config.SFTPRootDir == "" {
		return "", false
	}

	chrootPath := h.config.SFTPRootDir
	if !isValidDirectory(chrootPath) {
		h.logger.Warnf("Configured SFTP root directory %s not accessible or not a directory", chrootPath)
		return "", false
	}

	h.logger.Infof("SFTP using configured root directory for user %s: %s", username, chrootPath)
	return chrootPath, true
}

// getUserHomeChroot determines the chroot path based on user's home directory.
func (h *SFTPHandler) getUserHomeChroot(username string) (string, error) {
	userInfo, err := user.Lookup(username)
	if err != nil {
		h.logger.Warnf("User lookup failed for %s: %v", username, err)
		h.logger.Debugf("SFTP using filesystem root for user %s due to lookup failure", username)
		return "/", nil
	}

	chrootPath := userInfo.HomeDir
	if !isValidDirectory(chrootPath) {
		h.logger.Warnf("User home directory %s not accessible for %s", chrootPath, username)
		h.logger.Infof("SFTP fallback to filesystem root for user %s - consider creating home directory", username)
		return "/", nil
	}

	h.logger.Infof("SFTP chroot configured for user %s: %s", username, chrootPath)
	return chrootPath, nil
}

// isValidDirectory checks if a path exists and is a directory.
func isValidDirectory(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.IsDir()
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

// resolvePath resolves a request path against the working directory,
// treating workingDir as the SFTP root (matching OpenSSH ChrootDirectory
// semantics). Client-supplied absolute paths (e.g. "/etc/passwd") are
// interpreted as absolute *within* workingDir, not on the real filesystem -
// standard SFTP clients routinely send absolute paths, so workingDir must
// always be applied regardless of whether requestPath is absolute. Returns
// an error if the resolved path would escape workingDir.
// Hardening: Uses filepath.EvalSymlinks to detect symlink-based escape attempts,
// preventing pre-existing symlinks from bypassing the root directory restriction.
func (s *secureSFTPHandlers) resolvePath(requestPath string) (string, error) {
	root := filepath.Clean(s.workingDir)
	resolved := filepath.Clean(filepath.Join(root, requestPath))

	// A root of "/" (root user or no chroot configured) has nothing to escape.
	if root == string(filepath.Separator) {
		return resolved, nil
	}

	// First, check lexical path confinement (basic protection against ../ traversal)
	if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes configured root %q", requestPath, root)
	}

	// Second, resolve symlinks and re-check to prevent symlink-based escape
	// EvalSymlinks may fail if the path doesn't exist (file not yet created),
	// so we only validate if the path exists on the filesystem
	if evalResolved, err := filepath.EvalSymlinks(resolved); err == nil {
		// Path exists and symlinks were evaluated; verify the real path stays in bounds
		if evalResolved != root && !strings.HasPrefix(evalResolved, root+string(filepath.Separator)) {
			return "", fmt.Errorf("symlink in %q resolves outside configured root %q", requestPath, root)
		}
	}
	// If EvalSymlinks fails (path doesn't exist yet), that's OK - we allow creating new files

	return resolved, nil
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

	path, err := s.resolvePath(r.Filepath)
	if err != nil {
		s.handler.logger.Warnf("SFTP read denied for user %s: %v", s.username, err)
		return nil, err
	}

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
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP write denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return nil, err
	}

	path, err := s.resolvePath(r.Filepath)
	if err != nil {
		s.handler.logger.Warnf("SFTP write denied for user %s: %v", s.username, err)
		return nil, err
	}

	if err := s.handler.ValidateFileOperation(s.username, path, "write"); err != nil {
		s.handler.logger.Warnf("SFTP write denied for user %s on %s: %v", s.username, path, err)
		return nil, err
	}

	flags := buildOpenFileFlags(r.Pflags())

	if err := ensureParentDirectory(path); err != nil {
		return nil, err
	}

	return os.OpenFile(path, flags, 0o644)
}

// buildOpenFileFlags constructs file open flags from SFTP protocol flags.
func buildOpenFileFlags(pflags sftp.FileOpenFlags) int {
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

	return flags
}

// ensureParentDirectory creates the parent directory if it doesn't exist.
func ensureParentDirectory(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o755)
}

// Filecmd implements sftp.FileCmder - validates and handles file commands.
// Handles: Setstat, Rename, Rmdir, Mkdir, Link, Symlink, Remove
func (s *secureSFTPHandlers) Filecmd(r *sftp.Request) error {
	if err := s.validateFilecmdPaths(r); err != nil {
		return err
	}

	path, err := s.resolvePath(r.Filepath)
	if err != nil {
		s.handler.logger.Warnf("SFTP command denied for user %s: %v", s.username, err)
		return err
	}

	var targetPath string
	if r.Target != "" {
		targetPath, err = s.resolvePath(r.Target)
		if err != nil {
			s.handler.logger.Warnf("SFTP command denied for user %s: %v", s.username, err)
			return err
		}
	}

	operation := strings.ToLower(r.Method)

	if err := s.validateFilecmdOperation(path, targetPath, operation); err != nil {
		return err
	}

	return s.executeFilecmd(r.Method, path, targetPath, r)
}

// validateFilecmdPaths validates file and target paths for directory traversal.
func (s *secureSFTPHandlers) validateFilecmdPaths(r *sftp.Request) error {
	if err := s.checkDirectoryTraversal(r.Filepath); err != nil {
		s.handler.logger.Warnf("SFTP command denied for user %s: directory traversal attempt on %s", s.username, r.Filepath)
		return err
	}

	if r.Target != "" {
		if err := s.checkDirectoryTraversal(r.Target); err != nil {
			s.handler.logger.Warnf("SFTP command denied for user %s: directory traversal attempt on target %s", s.username, r.Target)
			return err
		}
	}

	return nil
}

// validateFilecmdOperation validates the file operation against security policies.
// path and targetPath must already be resolved (and confinement-checked) by the caller.
func (s *secureSFTPHandlers) validateFilecmdOperation(path, targetPath, operation string) error {
	if err := s.handler.ValidateFileOperation(s.username, path, operation); err != nil {
		s.handler.logger.Warnf("SFTP %s denied for user %s on %s: %v", operation, s.username, path, err)
		return err
	}

	if targetPath != "" {
		if err := s.handler.ValidateFileOperation(s.username, targetPath, operation); err != nil {
			s.handler.logger.Warnf("SFTP %s denied for user %s on target %s: %v", operation, s.username, targetPath, err)
			return err
		}
	}

	return nil
}

// executeFilecmd routes the file command to the appropriate handler.
// targetPath (if any) has already been resolved and confinement-checked by Filecmd.
func (s *secureSFTPHandlers) executeFilecmd(method, path, targetPath string, r *sftp.Request) error {
	switch method {
	case "Setstat":
		return s.handleSetstat(path, r)
	case "Rename":
		return os.Rename(path, targetPath)
	case "Rmdir":
		return os.Remove(path)
	case "Mkdir":
		return os.Mkdir(path, 0o755)
	case "Remove":
		return os.Remove(path)
	case "Symlink":
		return os.Symlink(path, targetPath)
	case "Link":
		return os.Link(path, targetPath)
	default:
		return errors.New("unsupported command: " + method)
	}
}

// handleSetstat handles the Setstat command for changing file attributes.
func (s *secureSFTPHandlers) handleSetstat(path string, r *sftp.Request) error {
	attrs := r.Attributes()
	attrFlags := r.AttrFlags()

	if err := applyPermissionsChange(path, attrs, attrFlags); err != nil {
		return err
	}

	if err := applyOwnershipChange(path, attrs, attrFlags); err != nil {
		return err
	}

	if err := applySizeChange(path, attrs, attrFlags); err != nil {
		return err
	}

	if err := applyTimeChange(path, attrs, attrFlags); err != nil {
		return err
	}

	return nil
}

// applyPermissionsChange updates file permissions if requested.
func applyPermissionsChange(path string, attrs *sftp.FileStat, attrFlags sftp.FileAttrFlags) error {
	if attrFlags.Permissions {
		return os.Chmod(path, attrs.FileMode())
	}
	return nil
}

// applyOwnershipChange updates file ownership if requested (requires root).
func applyOwnershipChange(path string, attrs *sftp.FileStat, attrFlags sftp.FileAttrFlags) error {
	if attrFlags.UidGid {
		uid := int(attrs.UID)
		gid := int(attrs.GID)
		return os.Chown(path, uid, gid)
	}
	return nil
}

// applySizeChange truncates the file to the specified size if requested.
func applySizeChange(path string, attrs *sftp.FileStat, attrFlags sftp.FileAttrFlags) error {
	if attrFlags.Size {
		return os.Truncate(path, int64(attrs.Size))
	}
	return nil
}

// applyTimeChange updates file access and modification times if requested.
func applyTimeChange(path string, attrs *sftp.FileStat, attrFlags sftp.FileAttrFlags) error {
	if attrFlags.Acmodtime {
		atime := time.Unix(int64(attrs.Atime), 0)
		mtime := time.Unix(int64(attrs.Mtime), 0)
		return os.Chtimes(path, atime, mtime)
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

	path, err := s.resolvePath(r.Filepath)
	if err != nil {
		s.handler.logger.Warnf("SFTP list denied for user %s: %v", s.username, err)
		return nil, err
	}

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
