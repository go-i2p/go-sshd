package handlers

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanDropPrivileges(t *testing.T) {
	// This test process is not expected to run as root under `go test`.
	assert.Equal(t, os.Getuid() == 0, canDropPrivileges())
}

func TestLookupUserCredential(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)

	cred, err := lookupUserCredential(current.Username)
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, current.Uid, strconv.FormatUint(uint64(cred.UID), 10))
	assert.Equal(t, current.Gid, strconv.FormatUint(uint64(cred.GID), 10))
	assert.NotEmpty(t, cred.Groups)
}

func TestLookupUserCredentialUnknownUser(t *testing.T) {
	_, err := lookupUserCredential("this-user-should-not-exist-go-sshd-test")
	assert.Error(t, err)
}

func TestExecCredential(t *testing.T) {
	cred := &userCredential{UID: 1001, GID: 1002, Groups: []uint32{1002, 27}}

	sysCred := execCredential(cred)

	require.NotNil(t, sysCred)
	assert.Equal(t, uint32(1001), sysCred.Uid)
	assert.Equal(t, uint32(1002), sysCred.Gid)
	assert.Equal(t, []uint32{1002, 27}, sysCred.Groups)
}

func TestWithDroppedPrivilegesNonRootIsPassthrough(t *testing.T) {
	if canDropPrivileges() {
		t.Skip("test process is running as root; passthrough behavior not exercised")
	}

	cred := &userCredential{UID: 0, GID: 0}
	called := false

	err := withDroppedPrivileges(cred, func() error {
		called = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, called, "fn should still run even when privileges cannot be dropped")
}

func TestWithDroppedPrivilegesPropagatesError(t *testing.T) {
	if canDropPrivileges() {
		t.Skip("test process is running as root; passthrough behavior not exercised")
	}

	cred := &userCredential{UID: 0, GID: 0}
	sentinel := errors.New("boom")

	err := withDroppedPrivileges(cred, func() error {
		return sentinel
	})

	assert.ErrorIs(t, err, sentinel)
}

func TestToIntGroups(t *testing.T) {
	assert.Equal(t, []int{1, 2, 3}, toIntGroups([]uint32{1, 2, 3}))
	assert.Equal(t, []int{}, toIntGroups([]uint32{}))
}

// TestApplyUserCredentialNonRootNoop verifies ShellHandler.applyUserCredential
// is a no-op (leaves SysProcAttr untouched) when the daemon is not running
// as root, matching prior exec.Cmd behavior of inheriting the caller's
// identity.
func TestApplyUserCredentialNonRootNoop(t *testing.T) {
	if canDropPrivileges() {
		t.Skip("test process is running as root; passthrough behavior not exercised")
	}

	handler := NewShellHandler(logrus.New())
	cmd := exec.Command("true")

	err := handler.applyUserCredential(cmd, "root")

	require.NoError(t, err)
	assert.Nil(t, cmd.SysProcAttr)
}
