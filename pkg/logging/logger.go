// Package logging provides centralized, configurable logging for the SSH server.package logging

// This package wraps sirupsen/logrus to provide OpenSSH-compatible logging functionality
// with structured logging, configurable output formats, and syslog integration.
package logging

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	logrussyslog "github.com/sirupsen/logrus/hooks/syslog"

	"github.com/go-i2p/go-sshd/pkg/config"
)

// Logger wraps logrus.Logger with SSH-specific context and OpenSSH-compatible configuration.
// This provides a centralized logging solution that matches OpenSSH behavior.
type Logger struct {
	*logrus.Logger
	level    string
	facility string
	filePath string
}

// NewLogger creates a configured logger from SSH configuration.
// Uses library-first approach - delegates to logrus with OpenSSH-compatible settings.
func NewLogger(cfg *config.Config) (*Logger, error) {
	logger := logrus.New()

	// Create wrapper with config
	l := &Logger{
		Logger:   logger,
		level:    cfg.LogLevel,
		facility: cfg.SyslogFacility,
		filePath: cfg.LogFile,
	}

	// Configure log level
	if err := l.setLogLevel(cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}

	// Configure output destination
	if err := l.setOutput(cfg.LogFile); err != nil {
		return nil, fmt.Errorf("failed to set log output: %w", err)
	}

	// Configure syslog if needed
	if err := l.configureSyslog(cfg.SyslogFacility); err != nil {
		return nil, fmt.Errorf("failed to configure syslog: %w", err)
	}

	// Set formatter based on output type
	l.setFormatter(cfg.LogFile)

	return l, nil
}

// WithContext creates a logger with contextual fields for session tracking.
// This enables tracing requests across handlers and components.
func (l *Logger) WithContext(sessionID, user, remoteAddr string) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"session_id":  sessionID,
		"user":        user,
		"remote_addr": remoteAddr,
	})
}

// WithSession creates a logger with session-specific context.
// Convenience method for SSH session logging.
func (l *Logger) WithSession(sessionID string) *logrus.Entry {
	return l.WithField("session_id", sessionID)
}

// GetLogrus returns the underlying logrus.Logger for compatibility with existing handlers.
// This allows handlers to continue using logrus while transitioning to centralized logging.
func (l *Logger) GetLogrus() *logrus.Logger {
	return l.Logger
}

// setLogLevel configures the logger level based on OpenSSH log levels.
// Maps OpenSSH levels to logrus levels for compatibility.
func (l *Logger) setLogLevel(level string) error {
	switch strings.ToUpper(level) {
	case "QUIET":
		l.SetLevel(logrus.PanicLevel) // Effectively silence all logging
	case "FATAL":
		l.SetLevel(logrus.FatalLevel)
	case "ERROR":
		l.SetLevel(logrus.ErrorLevel)
	case "INFO":
		l.SetLevel(logrus.InfoLevel)
	case "VERBOSE":
		l.SetLevel(logrus.InfoLevel) // Map to Info for compatibility
	case "DEBUG", "DEBUG1":
		l.SetLevel(logrus.DebugLevel)
	case "DEBUG2", "DEBUG3":
		l.SetLevel(logrus.TraceLevel) // Use trace for higher debug levels
	default:
		return fmt.Errorf("unsupported log level: %s", level)
	}
	return nil
}

// setOutput configures the logger output destination.
// Supports file output or stderr/stdout (when logFile is empty).
func (l *Logger) setOutput(logFile string) error {
	if logFile == "" {
		// Use stderr for logging (OpenSSH default)
		l.SetOutput(os.Stderr)
		return nil
	}

	// Open log file for writing
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", logFile, err)
	}

	// Set both stdout and file output
	multiWriter := io.MultiWriter(os.Stderr, file)
	l.SetOutput(multiWriter)
	return nil
}

// configureSyslog adds syslog hook if syslog facility is configured.
// Uses logrus syslog hook for system logging integration.
func (l *Logger) configureSyslog(facility string) error {
	if facility == "" {
		return nil // No syslog configuration
	}

	// Map OpenSSH facility to syslog priority
	priority, err := mapSyslogFacility(facility)
	if err != nil {
		return err
	}

	// Create syslog hook using logrus syslog hook
	hook, err := logrussyslog.NewSyslogHook("", "", priority, "sshd")
	if err != nil {
		return fmt.Errorf("failed to create syslog hook: %w", err)
	}

	l.AddHook(hook)
	return nil
}

// setFormatter configures log formatter based on output type.
// Uses JSON for files, text for console/stderr.
func (l *Logger) setFormatter(logFile string) {
	if logFile != "" {
		// Use JSON formatter for file output
		l.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	} else {
		// Use text formatter for console output
		l.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}
}

// mapSyslogFacility converts OpenSSH syslog facility to syslog priority.
// Maps OpenSSH facility strings to standard syslog facilities.
func mapSyslogFacility(facility string) (syslog.Priority, error) {
	switch strings.ToUpper(facility) {
	case "DAEMON":
		return syslog.LOG_DAEMON, nil
	case "USER":
		return syslog.LOG_USER, nil
	case "AUTH":
		return syslog.LOG_AUTH, nil
	case "AUTHPRIV":
		return syslog.LOG_AUTHPRIV, nil
	case "LOCAL0":
		return syslog.LOG_LOCAL0, nil
	case "LOCAL1":
		return syslog.LOG_LOCAL1, nil
	case "LOCAL2":
		return syslog.LOG_LOCAL2, nil
	case "LOCAL3":
		return syslog.LOG_LOCAL3, nil
	case "LOCAL4":
		return syslog.LOG_LOCAL4, nil
	case "LOCAL5":
		return syslog.LOG_LOCAL5, nil
	case "LOCAL6":
		return syslog.LOG_LOCAL6, nil
	case "LOCAL7":
		return syslog.LOG_LOCAL7, nil
	default:
		return 0, fmt.Errorf("unsupported syslog facility: %s", facility)
	}
}
