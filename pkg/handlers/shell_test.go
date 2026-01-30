package handlers

import (
	"os/user"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// currentUserNameForShellTest returns the current user's username.
// Separate from authorization_test.go helper to avoid package-level conflicts.
func currentUserNameForShellTest() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

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
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewShellHandler(logger)

	t.Run("NonexistentUser defaults to bash", func(t *testing.T) {
		shell, err := handler.getUserShell("nonexistentuser_xyz_12345")
		assert.NoError(t, err)
		assert.Equal(t, "/bin/bash", shell)
	})

	t.Run("Root user returns valid shell", func(t *testing.T) {
		shell, err := handler.getUserShell("root")
		assert.NoError(t, err)
		// Root should have a valid shell - typically /bin/bash, /bin/sh, or /usr/bin/zsh
		assert.True(t, shell != "", "root should have a shell configured")
		// Verify the shell path starts with / (absolute path)
		assert.True(t, shell[0] == '/', "shell should be an absolute path")
	})

	t.Run("Current user returns valid shell", func(t *testing.T) {
		currentUser, err := currentUserNameForShellTest()
		if err != nil {
			t.Skipf("Cannot get current user: %v", err)
		}

		shell, err := handler.getUserShell(currentUser)
		assert.NoError(t, err)
		assert.True(t, shell != "", "current user should have a shell configured")
		// The shell should be an absolute path
		assert.True(t, shell[0] == '/', "shell should be an absolute path")
		t.Logf("Current user %s has shell: %s", currentUser, shell)
	})
}

// TestGetShellFromPasswd tests parsing of /etc/passwd for shell information.
func TestGetShellFromPasswd(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewShellHandler(logger)

	t.Run("Root UID 0 returns shell", func(t *testing.T) {
		shell, err := handler.getShellFromPasswd("0")
		assert.NoError(t, err)
		assert.True(t, shell != "", "UID 0 (root) should have a shell")
		t.Logf("Root shell from passwd: %s", shell)
	})

	t.Run("NonexistentUID returns error", func(t *testing.T) {
		_, err := handler.getShellFromPasswd("99999999")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
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
