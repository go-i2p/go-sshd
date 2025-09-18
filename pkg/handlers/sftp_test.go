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
	options := handler.buildServerOptions()
	assert.NotNil(t, options)
	assert.GreaterOrEqual(t, len(options), 1) // At least working directory option

	// Test with debug log level
	logger.SetLevel(logrus.DebugLevel)
	debugOptions := handler.buildServerOptions()
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

	// Test chroot configuration (currently returns root)
	chrootPath, err := handler.ConfigureChroot("testuser")
	assert.NoError(t, err)
	assert.Equal(t, "/", chrootPath)
}

func TestValidateFileOperation(t *testing.T) {
	logger := logrus.New()
	cfg := &config.Config{}
	handler := NewSFTPHandler(cfg, logger)

	// Test file operation validation (currently allows all)
	err := handler.ValidateFileOperation("testuser", "/tmp/test.txt", "write")
	assert.NoError(t, err)

	err = handler.ValidateFileOperation("testuser", "/etc/passwd", "read")
	assert.NoError(t, err)
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
		options := handler.buildServerOptions()
		_ = options
	}
}
