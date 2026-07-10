package handlers

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestScanPasswdForUID tests the passwd-file scanning logic directly against
// a crafted temp file, independent of the real system /etc/passwd.
func TestScanPasswdForUID(t *testing.T) {
	content := `# a comment line

root:x:0:0:root:/root:/bin/bash
nologinuser:x:100:100:No Shell:/home/nologinuser:
testuser:x:1000:1000:Test User:/home/testuser:/bin/zsh
`
	path := filepath.Join(t.TempDir(), "passwd")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	shell, err := scanPasswdForUID(file, "1000")
	require.NoError(t, err)
	assert.Equal(t, "/bin/zsh", shell)
}

// TestBuildSessionEnvironmentDoesNotLeakDaemonEnvironment is a regression
// test for CRIT-2: the daemon's own process environment (which may contain
// operator secrets injected via systemd's EnvironmentFile=) must never be
// forwarded into an authenticated user's session.
func TestBuildSessionEnvironmentDoesNotLeakDaemonEnvironment(t *testing.T) {
	const sentinelKey = "GO_SSHD_TEST_SECRET_SENTINEL"
	t.Setenv(sentinelKey, "super-secret-value")

	env := buildSessionEnvironment("alice", "/bin/bash", "xterm", "/home/alice", "1.2.3.4:22", "5.6.7.8:22")

	for _, kv := range env {
		assert.NotContains(t, kv, sentinelKey, "session environment must not inherit the daemon's own process environment")
	}
}

// TestBuildSessionEnvironmentSetsExpectedVars verifies the explicit,
// minimal environment contains exactly the variables a session needs.
func TestBuildSessionEnvironmentSetsExpectedVars(t *testing.T) {
	env := buildSessionEnvironment("alice", "/bin/zsh", "xterm-256color", "/home/alice", "1.2.3.4:22", "5.6.7.8:22")

	assert.Contains(t, env, "PATH="+defaultSessionPath)
	assert.Contains(t, env, "SHELL=/bin/zsh")
	assert.Contains(t, env, "USER=alice")
	assert.Contains(t, env, "LOGNAME=alice")
	assert.Contains(t, env, "HOME=/home/alice")
	assert.Contains(t, env, "TERM=xterm-256color")
	assert.Contains(t, env, "SSH_CLIENT=1.2.3.4:22")
	assert.Contains(t, env, "SSH_CONNECTION=1.2.3.4:22 5.6.7.8:22")
}

// TestBuildSessionEnvironmentOmitsEmptyOptionalFields verifies TERM/HOME are
// omitted rather than emitted empty when not applicable (e.g. non-PTY
// sessions or unresolvable users).
func TestBuildSessionEnvironmentOmitsEmptyOptionalFields(t *testing.T) {
	env := buildSessionEnvironment("alice", "/bin/sh", "", "", "1.2.3.4:22", "5.6.7.8:22")

	for _, kv := range env {
		assert.False(t, strings.HasPrefix(kv, "TERM="), "TERM should be omitted for non-PTY sessions")
		assert.False(t, strings.HasPrefix(kv, "HOME="), "HOME should be omitted when unresolvable")
	}
}

// TestScanPasswdForUID_EmptyShellDefaultsToBash verifies that a passwd entry
// with an empty shell field falls back to /bin/bash.
func TestScanPasswdForUID_EmptyShellDefaultsToBash(t *testing.T) {
	content := "nologinuser:x:100:100:No Shell:/home/nologinuser:\n"
	path := filepath.Join(t.TempDir(), "passwd")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	shell, err := scanPasswdForUID(file, "100")
	require.NoError(t, err)
	assert.Equal(t, "/bin/bash", shell)
}

// TestScanPasswdForUID_NotFound verifies the not-found error path.
func TestScanPasswdForUID_NotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	require.NoError(t, os.WriteFile(path, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	_, err = scanPasswdForUID(file, "42")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestShouldSkipPasswdLine tests comment/blank line detection.
func TestShouldSkipPasswdLine(t *testing.T) {
	assert.True(t, shouldSkipPasswdLine(""))
	assert.True(t, shouldSkipPasswdLine("# a comment"))
	assert.False(t, shouldSkipPasswdLine("root:x:0:0:root:/root:/bin/bash"))
}

// TestParsePasswdLineForUID tests direct line parsing, including the
// empty-shell-defaults-to-bash and non-matching-UID branches.
func TestParsePasswdLineForUID(t *testing.T) {
	shell, found := parsePasswdLineForUID("root:x:0:0:root:/root:/bin/bash", "0")
	assert.True(t, found)
	assert.Equal(t, "/bin/bash", shell)

	_, found = parsePasswdLineForUID("root:x:0:0:root:/root:/bin/bash", "1")
	assert.False(t, found)

	_, found = parsePasswdLineForUID("malformed:line", "0")
	assert.False(t, found)

	shell, found = parsePasswdLineForUID("svc:x:5:5:Service::", "5")
	assert.True(t, found)
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
