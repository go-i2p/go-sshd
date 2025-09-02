package handlers

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewShellHandler(t *testing.T) {
	logger := logrus.New()
	handler := NewShellHandler(logger)

	assert.NotNil(t, handler)
	assert.Equal(t, logger, handler.logger)
}

func TestCreateSessionHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in tests
	handler := NewShellHandler(logger)

	sessionHandler := handler.CreateSessionHandler()
	assert.NotNil(t, sessionHandler)
}

func TestGetUserShell(t *testing.T) {
	logger := logrus.New()
	handler := NewShellHandler(logger)

	// Test with current user (should not error)
	shell, err := handler.getUserShell("root")
	assert.NoError(t, err)
	assert.Equal(t, "/bin/bash", shell) // Should default to bash

	// Test with non-existent user (should default to bash)
	shell, err = handler.getUserShell("nonexistentuser")
	assert.NoError(t, err)
	assert.Equal(t, "/bin/bash", shell)
}

func BenchmarkCreateSessionHandler(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise in benchmarks
	handler := NewShellHandler(logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionHandler := handler.CreateSessionHandler()
		_ = sessionHandler
	}
}
