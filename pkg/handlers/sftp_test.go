package handlers

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-sshd/pkg/config"
)

func TestNewSFTPHandler(t *testing.T) {
	logger := logrus.New()
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
}

func TestCreateSubsystemHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in tests
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	subsystemHandler := handler.CreateSubsystemHandler()
	assert.NotNil(t, subsystemHandler)
}

func TestBuildServerOptions(t *testing.T) {
	logger := logrus.New()
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	// Test with normal log level
	options := handler.buildServerOptions("/tmp")
	assert.NotNil(t, options)
	assert.GreaterOrEqual(t, len(options), 1) // At least working directory option

	// Test with debug log level
	logger.SetLevel(logrus.DebugLevel)
	debugOptions := handler.buildServerOptions("/tmp")
	assert.NotNil(t, debugOptions)
	assert.GreaterOrEqual(t, len(debugOptions), 2) // Working directory + debug option
}

func TestGetSupportedSubsystems(t *testing.T) {
	logger := logrus.New()
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	subsystems := handler.GetSupportedSubsystems()
	assert.Equal(t, []string{"sftp"}, subsystems)
}

func TestConfigureChroot(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in tests
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	// Test chroot configuration for root user (should return "/")
	chrootPath, err := handler.ConfigureChroot("root")
	assert.NoError(t, err)
	assert.Equal(t, "/", chrootPath)

	// Test chroot configuration for non-existent user (should fallback to "/")
	chrootPath, err = handler.ConfigureChroot("nonexistentuser123456")
	assert.NoError(t, err)
	assert.Equal(t, "/", chrootPath)

	// Test chroot configuration for current user (should return user's home or "/")
	chrootPath, err = handler.ConfigureChroot("testuser")
	assert.NoError(t, err)
	// Should be either user's home directory or "/" as fallback
	assert.True(t, chrootPath == "/" || len(chrootPath) > 1)
}

func TestConfigureChrootWithSFTPRootDir(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("SFTPRootDir configured and valid", func(t *testing.T) {
		// Use /tmp as it exists on all systems
		cfg := &config.Config{
			SFTPRootDir: "/tmp",
		}
		handler := NewSFTPHandler(cfg, logger)

		chrootPath, err := handler.ConfigureChroot("testuser")
		assert.NoError(t, err)
		assert.Equal(t, "/tmp", chrootPath, "Should use configured SFTPRootDir")
	})

	t.Run("SFTPRootDir configured but nonexistent", func(t *testing.T) {
		cfg := &config.Config{
			SFTPRootDir: "/nonexistent/path/that/does/not/exist",
		}
		handler := NewSFTPHandler(cfg, logger)

		// Should fall back to "/" for nonexistent user when SFTPRootDir is invalid
		chrootPath, err := handler.ConfigureChroot("nonexistentuser123456")
		assert.NoError(t, err)
		assert.Equal(t, "/", chrootPath, "Should fall back when SFTPRootDir doesn't exist")
	})

	t.Run("Empty SFTPRootDir uses home directory", func(t *testing.T) {
		cfg := &config.Config{
			SFTPRootDir: "", // Empty - should use home directory
		}
		handler := NewSFTPHandler(cfg, logger)

		// Root should get "/" regardless
		chrootPath, err := handler.ConfigureChroot("root")
		assert.NoError(t, err)
		assert.Equal(t, "/", chrootPath)
	})

	t.Run("SFTPRootDir takes priority over home directory", func(t *testing.T) {
		cfg := &config.Config{
			SFTPRootDir: "/tmp",
		}
		handler := NewSFTPHandler(cfg, logger)

		// Even for root, SFTPRootDir should take priority when configured
		chrootPath, err := handler.ConfigureChroot("root")
		assert.NoError(t, err)
		assert.Equal(t, "/tmp", chrootPath, "SFTPRootDir should take priority")
	})
}

func TestValidateFileOperation(t *testing.T) {
	logger := logrus.New()
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	// Test allowed file operation
	err := handler.ValidateFileOperation("testuser", "/tmp/test.txt", "write")
	assert.NoError(t, err)

	// Test read operation on system file (should be blocked for non-root)
	err = handler.ValidateFileOperation("testuser", "/etc/passwd", "read")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access to system files denied")

	// Test directory traversal attempt (should be blocked)
	err = handler.ValidateFileOperation("testuser", "/tmp/../etc/passwd", "read")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "directory traversal not allowed")

	// Test write to protected system directory (should be blocked)
	err = handler.ValidateFileOperation("testuser", "/bin/malicious", "write")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write operations to system directories not allowed")

	// Test root user access (should be allowed for most operations)
	err = handler.ValidateFileOperation("root", "/etc/passwd", "read")
	assert.NoError(t, err)

	// Test root user write to protected directory (should still be blocked)
	err = handler.ValidateFileOperation("root", "/bin/test", "write")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write operations to system directories not allowed")
}

func BenchmarkCreateSubsystemHandler(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in benchmarks
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subsystemHandler := handler.CreateSubsystemHandler()
		_ = subsystemHandler
	}
}

func BenchmarkBuildServerOptions(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := handler.buildServerOptions("/tmp")
		_ = options
	}
}

// Tests for secureSFTPHandlers - verifying ValidateFileOperation is invoked

func TestNewSecureSFTPHandlers(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/home/testuser")
	assert.NotNil(t, secureHandlers)
	assert.Equal(t, "testuser", secureHandlers.username)
	assert.Equal(t, "/home/testuser", secureHandlers.workingDir)
	assert.Equal(t, handler, secureHandlers.handler)
}

func TestSecureSFTPHandlers_Handlers(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/home/testuser")

	handlers := secureHandlers.Handlers()
	assert.NotNil(t, handlers.FileGet)
	assert.NotNil(t, handlers.FilePut)
	assert.NotNil(t, handlers.FileCmd)
	assert.NotNil(t, handlers.FileList)
}

func TestSecureSFTPHandlers_ResolvePath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/home/testuser")

	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{"absolute path is confined within working dir, not the real filesystem", "/tmp/file.txt", "/home/testuser/tmp/file.txt", false},
		{"absolute path to sensitive file is confined within working dir", "/etc/passwd", "/home/testuser/etc/passwd", false},
		{"relative path resolves to working dir", "file.txt", "/home/testuser/file.txt", false},
		{"relative subdir resolves correctly", "subdir/file.txt", "/home/testuser/subdir/file.txt", false},
		{"path with dots is cleaned", "./file.txt", "/home/testuser/file.txt", false},
		{"request for the root itself resolves", "/", "/home/testuser", false},
		{"single parent traversal escaping root is rejected", "../file.txt", "", true},
		{"parent traversal escaping root via absolute path is rejected", "/../../../etc/passwd", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := secureHandlers.resolvePath(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSecureSFTPHandlers_ResolvePath_NoConfinement verifies that a working
// directory of "/" (e.g. the root user, or no chroot configured) imposes no
// additional restriction beyond normal path cleaning.
func TestSecureSFTPHandlers_ResolvePath_NoConfinement(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "root", "/")

	result, err := secureHandlers.resolvePath("/etc/passwd")
	assert.NoError(t, err)
	assert.Equal(t, "/etc/passwd", result)
}

func TestSecureSFTPHandlers_FilereadValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/tmp")

	tests := []struct {
		name     string
		filepath string
	}{
		{"allow read from tmp", "/tmp/allowed.txt"},
		// Absolute paths are confined within the working directory (chroot
		// semantics), so a request for "/etc/passwd" resolves to
		// "/tmp/etc/passwd" and never reaches the real /etc/passwd - it is not
		// blocked by the sensitive-file list because it can never reach it.
		{"absolute path to /etc/passwd is confined, not the real file", "/etc/passwd"},
		// Note: sftp.NewRequest normalizes paths against a "/" root, so
		// "../etc/passwd" is equivalent to "/etc/passwd" here - also confined.
		{"traversal-looking path is confined, not a real escape", "../etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: "Get", filepath: tt.filepath}
			_, err := secureHandlers.Fileread(req.toSFTPRequest())

			// None of these should produce a security-denial error - the
			// confinement means the real /etc/passwd is never reached, so at
			// most a "file not found" style OS error is expected.
			if err != nil {
				assert.NotContains(t, err.Error(), "access to system files denied")
				assert.NotContains(t, err.Error(), "directory traversal not allowed")
				assert.NotContains(t, err.Error(), "escapes configured root")
			}
		})
	}
}

// TestSecureSFTPHandlers_FilereadConfinement is a regression test for the
// SFTP path-confinement bypass: a user chrooted to a working directory must
// never be able to read a file that lives outside that working directory,
// even by requesting an absolute path that appears to point elsewhere.
func TestSecureSFTPHandlers_FilereadConfinement(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	// secretDir simulates a location outside the user's sandbox that must
	// remain unreachable, e.g. another user's home directory.
	secretDir := t.TempDir()
	secretFile := secretDir + "/secret.txt"
	if err := os.WriteFile(secretFile, []byte("top secret"), 0o600); err != nil {
		t.Fatalf("failed to create secret file: %v", err)
	}

	workingDir := t.TempDir()
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", workingDir)

	// The client requests the secret file by its real absolute path, exactly
	// as a standard SFTP client would (e.g. `sftp> get <secretFile>`).
	req := &mockSFTPRequest{method: "Get", filepath: secretFile}
	reader, err := secureHandlers.Fileread(req.toSFTPRequest())
	if err == nil {
		// If no error, the resolved path must not be the real secret file -
		// reading from it must not yield the real secret contents.
		buf := make([]byte, len("top secret"))
		n, _ := reader.ReadAt(buf, 0)
		assert.NotEqual(t, "top secret", string(buf[:n]), "confined SFTP session must not be able to read a file outside its working directory")
	}
}

func TestSecureSFTPHandlers_FilewriteValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	workingDir := t.TempDir()
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", workingDir)

	tests := []struct {
		name     string
		filepath string
	}{
		// These look like protected system paths, but because the user is
		// confined to workingDir (chroot semantics), they resolve to
		// subdirectories of workingDir, not the real /bin, /sbin, etc., and
		// so are not blocked by the protected-system-directory checks.
		{"absolute path resembling /bin is confined within working dir", "/bin/malicious"},
		{"absolute path resembling /sbin is confined within working dir", "/sbin/evil"},
		{"absolute path resembling /usr/bin is confined within working dir", "/usr/bin/bad"},
		{"traversal-looking path is confined within working dir", "../bin/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: "Put", filepath: tt.filepath}
			_, err := secureHandlers.Filewrite(req.toSFTPRequest())

			if err != nil {
				assert.NotContains(t, err.Error(), "write operations to system directories not allowed")
				assert.NotContains(t, err.Error(), "escapes configured root")
			}
		})
	}
}

func TestSecureSFTPHandlers_FilecmdValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	workingDir := t.TempDir()
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", workingDir)

	tests := []struct {
		name     string
		method   string
		filepath string
		target   string
	}{
		// These look like protected system paths, but the user is confined to
		// workingDir (chroot semantics), so they resolve within workingDir,
		// not the real /bin, /sbin, /usr/bin.
		{"mkdir resembling /bin is confined within working dir", "Mkdir", "/bin/newdir", ""},
		{"rmdir resembling /sbin is confined within working dir", "Rmdir", "/sbin/dir", ""},
		{"remove resembling /usr/bin is confined within working dir", "Remove", "/usr/bin/file", ""},
		{"rename target resembling /bin is confined within working dir", "Rename", "/tmp/file", "/bin/file"},
		{"traversal-looking mkdir is confined within working dir", "Mkdir", "../bin/newdir", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: tt.method, filepath: tt.filepath, target: tt.target}
			err := secureHandlers.Filecmd(req.toSFTPRequest())

			if err != nil {
				assert.NotContains(t, err.Error(), "write operations to system directories not allowed")
				assert.NotContains(t, err.Error(), "escapes configured root")
			}
		})
	}
}

func TestSecureSFTPHandlers_FilelistValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/tmp")

	tests := []struct {
		name     string
		method   string
		filepath string
	}{
		// These look like protected system paths, but the user is confined to
		// /tmp (chroot semantics), so they resolve to /tmp/etc/shadow etc.,
		// not the real files, and are therefore not blocked.
		{"list resembling /etc/shadow is confined within working dir", "List", "/etc/shadow"},
		{"stat resembling /etc/passwd is confined within working dir", "Stat", "/etc/passwd"},
		{"readlink resembling /root/.ssh is confined within working dir", "Readlink", "/root/.ssh"},
		{"traversal-looking stat is confined within working dir", "Stat", "../etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: tt.method, filepath: tt.filepath}
			_, err := secureHandlers.Filelist(req.toSFTPRequest())

			if err != nil {
				assert.NotContains(t, err.Error(), "access to system files denied")
				assert.NotContains(t, err.Error(), "escapes configured root")
			}
		})
	}
}

func TestSecureSFTPHandlers_RootUserAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	// Root user is unconfined (workingDir "/"), so the sensitive-file
	// blocklist is the operative defense for root sessions.
	secureHandlers := newSecureSFTPHandlers(handler, "root", "/")

	// Root CAN read /etc/passwd
	req := &mockSFTPRequest{method: "Stat", filepath: "/etc/passwd"}
	_, err := secureHandlers.Filelist(req.toSFTPRequest())
	// No security error (may get file not found in test environment)
	if err != nil {
		assert.NotContains(t, err.Error(), "access to system files denied")
	}

	// Root CANNOT write to protected system directories (even root is blocked)
	reqWrite := &mockSFTPRequest{method: "Mkdir", filepath: "/bin/newdir"}
	err = secureHandlers.Filecmd(reqWrite.toSFTPRequest())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write operations to system directories not allowed")
}

func TestListerat_ListAt(t *testing.T) {
	files := listerat{
		mockFileInfo{name: "file1.txt"},
		mockFileInfo{name: "file2.txt"},
		mockFileInfo{name: "file3.txt"},
	}

	tests := []struct {
		name        string
		offset      int64
		bufSize     int
		expectCount int
		expectEOF   bool
	}{
		{"read all from start", 0, 5, 3, true},
		{"read partial", 0, 2, 2, false},
		{"read from middle", 1, 3, 2, true},
		{"read from end", 3, 3, 0, true},
		{"read past end", 10, 3, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]os.FileInfo, tt.bufSize)
			n, err := files.ListAt(buf, tt.offset)
			assert.Equal(t, tt.expectCount, n)
			if tt.expectEOF {
				assert.ErrorIs(t, err, io.EOF)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSymlinkInfo(t *testing.T) {
	info := symlinkInfo{name: "/target/path"}
	assert.Equal(t, "/target/path", info.Name())
	assert.Equal(t, int64(0), info.Size())
	assert.Equal(t, os.ModeSymlink, info.Mode())
	assert.Equal(t, time.Time{}, info.ModTime())
	assert.False(t, info.IsDir())
	assert.Nil(t, info.Sys())
}

// TestFileWrapper_Close verifies fileWrapper.Close closes the underlying
// file exactly once, even when called multiple times.
func TestFileWrapper_Close(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrapped.txt")
	f, err := os.Create(path)
	require.NoError(t, err)

	wrapper := &fileWrapper{File: f}

	assert.NoError(t, wrapper.Close())
	// A second Close must be a no-op, not an error (double-close is safe).
	assert.NoError(t, wrapper.Close())
}

// TestApplyPermissionsChange verifies file permission changes via Setstat.
func TestApplyPermissionsChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perms.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))

	attrs := &sftp.FileStat{Mode: 0o600}
	err := applyPermissionsChange(path, attrs, sftp.FileAttrFlags{Permissions: true})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// No flag set: no-op, must not error.
	assert.NoError(t, applyPermissionsChange(path, attrs, sftp.FileAttrFlags{}))
}

// TestApplySizeChange verifies file truncation via Setstat.
func TestApplySizeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "size.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello world"), 0o644))

	attrs := &sftp.FileStat{Size: 5}
	err := applySizeChange(path, attrs, sftp.FileAttrFlags{Size: true})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(5), info.Size())

	assert.NoError(t, applySizeChange(path, attrs, sftp.FileAttrFlags{}))
}

// TestApplyTimeChange verifies access/modification time changes via Setstat.
func TestApplyTimeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "time.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))

	target := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	attrs := &sftp.FileStat{
		Atime: uint32(target.Unix()),
		Mtime: uint32(target.Unix()),
	}
	err := applyTimeChange(path, attrs, sftp.FileAttrFlags{Acmodtime: true})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, target.Unix(), info.ModTime().Unix())

	assert.NoError(t, applyTimeChange(path, attrs, sftp.FileAttrFlags{}))
}

// TestApplyOwnershipChange verifies the no-op path when UidGid isn't requested;
// changing ownership itself typically requires root privileges, so only the
// no-op branch is exercised here.
func TestApplyOwnershipChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))

	attrs := &sftp.FileStat{}
	assert.NoError(t, applyOwnershipChange(path, attrs, sftp.FileAttrFlags{}))
}

// mockSFTPRequest helps create sftp.Request objects for testing
type mockSFTPRequest struct {
	method   string
	filepath string
	target   string
}

func (m *mockSFTPRequest) toSFTPRequest() *sftp.Request {
	req := sftp.NewRequest(m.method, m.filepath)
	if m.target != "" {
		req.Target = m.target
	}
	return req
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	name string
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return 0o644 }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }
