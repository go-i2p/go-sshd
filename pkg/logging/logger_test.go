package logging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-i2p/go-sshd/pkg/config"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name: "default config",
			config: &config.Config{
				LogLevel:       "INFO",
				SyslogFacility: "AUTH",
				LogFile:        "",
			},
			wantErr: false,
		},
		{
			name: "debug level",
			config: &config.Config{
				LogLevel:       "DEBUG",
				SyslogFacility: "",
				LogFile:        "",
			},
			wantErr: false,
		},
		{
			name: "invalid log level",
			config: &config.Config{
				LogLevel:       "INVALID",
				SyslogFacility: "",
				LogFile:        "",
			},
			wantErr: true,
		},
		{
			name: "invalid syslog facility",
			config: &config.Config{
				LogLevel:       "INFO",
				SyslogFacility: "INVALID",
				LogFile:        "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		configLevel string
		logrusLevel logrus.Level
	}{
		{"QUIET", logrus.PanicLevel},
		{"FATAL", logrus.FatalLevel},
		{"ERROR", logrus.ErrorLevel},
		{"INFO", logrus.InfoLevel},
		{"VERBOSE", logrus.InfoLevel},
		{"DEBUG", logrus.DebugLevel},
		{"DEBUG1", logrus.DebugLevel},
		{"DEBUG2", logrus.TraceLevel},
		{"DEBUG3", logrus.TraceLevel},
	}

	for _, tt := range tests {
		t.Run(tt.configLevel, func(t *testing.T) {
			cfg := &config.Config{
				LogLevel:       tt.configLevel,
				SyslogFacility: "",
				LogFile:        "",
			}

			logger, err := NewLogger(cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.logrusLevel, logger.GetLevel())
		})
	}
}

func TestLogFile(t *testing.T) {
	// Create temporary log file
	tmpDir, err := os.MkdirTemp("", "sshd-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "test.log")

	cfg := &config.Config{
		LogLevel:       "INFO",
		SyslogFacility: "",
		LogFile:        logFile,
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	// Test that we can write to the log
	logger.Info("test message")

	// Verify log file was created
	_, err = os.Stat(logFile)
	assert.NoError(t, err)
}

func TestWithContext(t *testing.T) {
	cfg := &config.Config{
		LogLevel:       "INFO",
		SyslogFacility: "",
		LogFile:        "",
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	entry := logger.WithContext("session123", "testuser", "192.168.1.100")

	// Verify fields are set
	assert.Equal(t, "session123", entry.Data["session_id"])
	assert.Equal(t, "testuser", entry.Data["user"])
	assert.Equal(t, "192.168.1.100", entry.Data["remote_addr"])
}

func TestWithSession(t *testing.T) {
	cfg := &config.Config{
		LogLevel:       "INFO",
		SyslogFacility: "",
		LogFile:        "",
	}

	logger, err := NewLogger(cfg)
	require.NoError(t, err)

	entry := logger.WithSession("session456")

	// Verify session ID field is set
	assert.Equal(t, "session456", entry.Data["session_id"])
}

func TestMapSyslogFacility(t *testing.T) {
	tests := []struct {
		facility string
		wantErr  bool
	}{
		{"DAEMON", false},
		{"USER", false},
		{"AUTH", false},
		{"AUTHPRIV", false},
		{"LOCAL0", false},
		{"LOCAL1", false},
		{"LOCAL2", false},
		{"LOCAL3", false},
		{"LOCAL4", false},
		{"LOCAL5", false},
		{"LOCAL6", false},
		{"LOCAL7", false},
		{"INVALID", true},
	}

	for _, tt := range tests {
		t.Run(tt.facility, func(t *testing.T) {
			_, err := mapSyslogFacility(tt.facility)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
