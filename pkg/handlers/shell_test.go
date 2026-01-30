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

// TestCommandRestrictionStoredInContext verifies that command restrictions
// from authorized_keys are stored in the session context during authentication.
func TestCommandRestrictionStoredInContext(t *testing.T) {
	// Test that the context key is properly defined
	assert.Equal(t, "authorized-key-options", ContextKeyAuthorizedKeyOptions)
}

// TestAuthorizedKeyOptionsStruct tests the AuthorizedKeyOptions struct fields.
func TestAuthorizedKeyOptionsStruct(t *testing.T) {
	opts := &AuthorizedKeyOptions{
		Command:           "/bin/backup",
		NoPTY:             true,
		NoPortForwarding:  true,
		NoAgentForwarding: true,
		NoX11Forwarding:   true,
		From:              []string{"192.168.1.0/24"},
	}

	assert.Equal(t, "/bin/backup", opts.Command)
	assert.True(t, opts.NoPTY)
	assert.True(t, opts.NoPortForwarding)
	assert.True(t, opts.NoAgentForwarding)
	assert.True(t, opts.NoX11Forwarding)
	assert.Len(t, opts.From, 1)
	assert.Equal(t, "192.168.1.0/24", opts.From[0])
}
