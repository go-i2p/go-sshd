// Package handlers provides SSH protocol handlers for authentication, sessions, and subsystems.
// This package wraps mature libraries to provide OpenSSH-compatible functionality.
package handlers

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
)

// userCredential holds the resolved UID/GID/supplementary groups for a
// system user. It is used to drop the daemon's own privileges (normally
// root, per systemd/sshd-go.service) down to the authenticated user's
// privileges before executing shells, forced commands, or SFTP file
// operations on that user's behalf - matching standard OpenSSH behavior.
type userCredential struct {
	UID    uint32
	GID    uint32
	Groups []uint32
}

// lookupUserCredential resolves the UID, primary GID, and supplementary
// group IDs for username via os/user.
func lookupUserCredential(username string) (*userCredential, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup user %s: %w", username, err)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse uid for %s: %w", username, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse gid for %s: %w", username, err)
	}

	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("lookup groups for %s: %w", username, err)
	}
	groups := make([]uint32, 0, len(groupIDs))
	for _, g := range groupIDs {
		gidVal, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			continue
		}
		groups = append(groups, uint32(gidVal))
	}

	return &userCredential{UID: uint32(uid), GID: uint32(gid), Groups: groups}, nil
}

// canDropPrivileges reports whether the current process is running with the
// privilege (UID 0) required to switch to another user's credential. When
// false, privilege dropping is skipped rather than failed closed: a
// non-root daemon process cannot switch users regardless, which matches
// both how the daemon is expected to run in production (as root, per
// systemd/sshd-go.service) and how it is normally run in tests/manual
// development (as an unprivileged user, unable to change identity at all).
func canDropPrivileges() bool {
	return os.Getuid() == 0
}

// execCredential builds a syscall.Credential for use as
// exec.Cmd.SysProcAttr.Credential, so the spawned child process runs as
// cred's user rather than inheriting the daemon's own (root) identity.
func execCredential(cred *userCredential) *syscall.Credential {
	return &syscall.Credential{
		Uid:    cred.UID,
		Gid:    cred.GID,
		Groups: cred.Groups,
	}
}

// withDroppedPrivileges runs fn after switching the calling goroutine's
// underlying OS thread credentials to cred, then restores root before
// returning. It is used to confine an entire SFTP session's file
// operations to the authenticated user's privilege level instead of the
// daemon's own.
//
// Linux credentials (setresuid/setresgid) are a per-OS-thread property, not
// a per-process one, so the goroutine's OS thread is pinned for the
// duration via runtime.LockOSThread to prevent the Go scheduler from
// running this goroutine - or any other goroutine - on a thread with the
// wrong privilege level. If privileges cannot be restored to root
// afterward, the thread is deliberately left locked (never unlocked) so
// the Go runtime terminates it instead of returning a stuck low-privilege
// (or, if restoration failed, unpredictable) thread to the scheduler for
// reuse by unrelated, differently-privileged work.
func withDroppedPrivileges(cred *userCredential, fn func() error) error {
	if !canDropPrivileges() {
		return fn()
	}

	runtime.LockOSThread()

	if err := dropThreadPrivileges(cred); err != nil {
		runtime.UnlockOSThread()
		return err
	}

	fnErr := fn()

	if err := restoreRootPrivileges(); err != nil {
		// Do not unlock: leave the thread pinned so the runtime tears it
		// down rather than reusing it at an unknown privilege level.
		return err
	}

	runtime.UnlockOSThread()
	return fnErr
}

// dropThreadPrivileges switches the current OS thread's groups/GID/UID to
// cred, preserving a saved-UID/GID of 0 (root) so root can be restored
// later via restoreRootPrivileges.
func dropThreadPrivileges(cred *userCredential) error {
	if err := syscall.Setgroups(toIntGroups(cred.Groups)); err != nil {
		return fmt.Errorf("set supplementary groups: %w", err)
	}
	if err := syscall.Setresgid(int(cred.GID), int(cred.GID), 0); err != nil {
		return fmt.Errorf("drop group privileges: %w", err)
	}
	if err := syscall.Setresuid(int(cred.UID), int(cred.UID), 0); err != nil {
		return fmt.Errorf("drop user privileges: %w", err)
	}
	return nil
}

// restoreRootPrivileges restores the current OS thread's UID/GID to root
// (0), relying on the saved-UID/GID of 0 preserved by dropThreadPrivileges.
func restoreRootPrivileges() error {
	if err := syscall.Setresuid(0, 0, 0); err != nil {
		return fmt.Errorf("restore root privileges (thread terminated): %w", err)
	}
	if err := syscall.Setresgid(0, 0, 0); err != nil {
		return fmt.Errorf("restore root group privileges (thread terminated): %w", err)
	}
	return nil
}

// toIntGroups converts a slice of uint32 group IDs to []int, as required by
// syscall.Setgroups.
func toIntGroups(groups []uint32) []int {
	out := make([]int, len(groups))
	for i, g := range groups {
		out[i] = int(g)
	}
	return out
}
