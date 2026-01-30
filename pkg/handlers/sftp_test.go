package handlers

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

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
		name     string
		input    string
		expected string
	}{
		{"absolute path stays absolute", "/tmp/file.txt", "/tmp/file.txt"},
		{"relative path resolves to working dir", "file.txt", "/home/testuser/file.txt"},
		{"relative subdir resolves correctly", "subdir/file.txt", "/home/testuser/subdir/file.txt"},
		{"path with dots is cleaned", "./file.txt", "/home/testuser/file.txt"},
		{"path with parent traversal is cleaned", "../file.txt", "/home/file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := secureHandlers.resolvePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecureSFTPHandlers_FilereadValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/tmp")

	tests := []struct {
		name          string
		filepath      string
		expectError   bool
		errorContains string
	}{
		{"allow read from tmp", "/tmp/allowed.txt", false, ""},
		{"block read from /etc/passwd", "/etc/passwd", true, "access to system files denied"},
		// Note: sftp.NewRequest cleans paths, so "../etc/passwd" becomes "/etc/passwd"
		// The security still works because /etc/passwd is blocked as a sensitive file
		{"block traversal via path cleaning", "../etc/passwd", true, "access to system files denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock request
			req := &mockSFTPRequest{method: "Get", filepath: tt.filepath}
			_, err := secureHandlers.Fileread(req.toSFTPRequest())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				// For allowed paths, we may get file not found errors (expected)
				// but not security errors
				if err != nil {
					assert.NotContains(t, err.Error(), "access to system files denied")
					assert.NotContains(t, err.Error(), "directory traversal not allowed")
				}
			}
		})
	}
}

func TestSecureSFTPHandlers_FilewriteValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/tmp")

	tests := []struct {
		name          string
		filepath      string
		expectError   bool
		errorContains string
	}{
		{"block write to /bin", "/bin/malicious", true, "write operations to system directories not allowed"},
		{"block write to /sbin", "/sbin/evil", true, "write operations to system directories not allowed"},
		{"block write to /usr/bin", "/usr/bin/bad", true, "write operations to system directories not allowed"},
		// Note: sftp.NewRequest cleans paths, so "../bin/test" becomes "/bin/test"
		{"block traversal via path cleaning", "../bin/test", true, "write operations to system directories not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: "Put", filepath: tt.filepath}
			_, err := secureHandlers.Filewrite(req.toSFTPRequest())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			}
		})
	}
}

func TestSecureSFTPHandlers_FilecmdValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	secureHandlers := newSecureSFTPHandlers(handler, "testuser", "/tmp")

	tests := []struct {
		name          string
		method        string
		filepath      string
		target        string
		expectError   bool
		errorContains string
	}{
		{"block mkdir in /bin", "Mkdir", "/bin/newdir", "", true, "write operations to system directories not allowed"},
		{"block rmdir in /sbin", "Rmdir", "/sbin/dir", "", true, "write operations to system directories not allowed"},
		{"block remove in /usr/bin", "Remove", "/usr/bin/file", "", true, "write operations to system directories not allowed"},
		{"block rename to protected dir", "Rename", "/tmp/file", "/bin/file", true, "write operations to system directories not allowed"},
		// Note: sftp.NewRequest cleans paths, so "../bin/newdir" becomes "/bin/newdir"
		{"block traversal via path cleaning", "Mkdir", "../bin/newdir", "", true, "write operations to system directories not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: tt.method, filepath: tt.filepath, target: tt.target}
			err := secureHandlers.Filecmd(req.toSFTPRequest())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
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
		name          string
		method        string
		filepath      string
		expectError   bool
		errorContains string
	}{
		{"block list /etc/shadow", "List", "/etc/shadow", true, "access to system files denied"},
		{"block stat /etc/passwd", "Stat", "/etc/passwd", true, "access to system files denied"},
		{"block readlink sensitive path", "Readlink", "/root/.ssh", true, "access to system files denied"},
		// Note: sftp.NewRequest cleans paths, so "../etc/" becomes "/etc"
		// /etc is blocked because /etc/passwd, /etc/shadow, /etc/ssh are all protected
		{"block traversal via path cleaning", "Stat", "../etc/passwd", true, "access to system files denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &mockSFTPRequest{method: tt.method, filepath: tt.filepath}
			result, err := secureHandlers.Filelist(req.toSFTPRequest())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestSecureSFTPHandlers_RootUserAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)
	// Root user should be able to read system files but not write to protected dirs
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
	assert.False(t, info.IsDir())
	assert.Nil(t, info.Sys())
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
