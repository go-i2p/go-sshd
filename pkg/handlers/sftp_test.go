package handlers

import (
	"testing"

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
