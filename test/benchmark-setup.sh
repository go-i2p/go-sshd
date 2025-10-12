#!/bin/bash
# Performance Benchmark Setup Script
#
# This script automates the setup required for running performance benchmarks.
# It follows the library-first philosophy by using standard system tools.
#
# Requirements:
# - Root access (for user creation and sshd configuration)
# - OpenSSH client tools (ssh, ssh-keygen)
# - Go 1.21+ toolchain
#
# Usage:
#   sudo ./benchmark-setup.sh       # Full setup
#   sudo ./benchmark-setup.sh clean # Clean up test environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_USER="testuser"
TEST_KEY_PATH="$SCRIPT_DIR/testdata/test_rsa"
SSHD_GO_PORT=2222
OPENSSH_PORT=2223

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Usage: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    command -v ssh-keygen >/dev/null 2>&1 || missing_deps+=("openssh-client")
    command -v go >/dev/null 2>&1 || missing_deps+=("golang")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    log_info "All dependencies satisfied"
}

create_test_key() {
    log_info "Creating test SSH key pair..."
    
    mkdir -p "$SCRIPT_DIR/testdata"
    
    if [[ -f "$TEST_KEY_PATH" ]]; then
        log_warn "Test key already exists at $TEST_KEY_PATH"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing key"
            return
        fi
        rm -f "$TEST_KEY_PATH" "${TEST_KEY_PATH}.pub"
    fi
    
    ssh-keygen -t rsa -b 2048 -f "$TEST_KEY_PATH" -N "" -C "sshd-go benchmark test key"
    chmod 600 "$TEST_KEY_PATH"
    chmod 644 "${TEST_KEY_PATH}.pub"
    
    log_info "Test key created: $TEST_KEY_PATH"
}

create_test_user() {
    log_info "Creating test user: $TEST_USER..."
    
    if id "$TEST_USER" &>/dev/null; then
        log_warn "User $TEST_USER already exists"
        return
    fi
    
    useradd -m -s /bin/bash "$TEST_USER"
    
    # Setup SSH directory
    local user_home="/home/$TEST_USER"
    mkdir -p "$user_home/.ssh"
    cp "${TEST_KEY_PATH}.pub" "$user_home/.ssh/authorized_keys"
    
    chown -R "$TEST_USER:$TEST_USER" "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    chmod 600 "$user_home/.ssh/authorized_keys"
    
    log_info "Test user $TEST_USER created with authorized key"
}

build_sshd_go() {
    log_info "Building sshd-go binary..."
    
    cd "$PROJECT_ROOT"
    
    if ! go build -o sshd cmd/sshd/main.go; then
        log_error "Failed to build sshd-go"
        exit 1
    fi
    
    chmod +x sshd
    log_info "sshd-go built successfully: $PROJECT_ROOT/sshd"
}

verify_setup() {
    log_info "Verifying benchmark setup..."
    
    local errors=0
    
    # Check test key
    if [[ ! -f "$TEST_KEY_PATH" ]]; then
        log_error "Test key not found: $TEST_KEY_PATH"
        ((errors++))
    fi
    
    # Check test user
    if ! id "$TEST_USER" &>/dev/null; then
        log_error "Test user $TEST_USER does not exist"
        ((errors++))
    fi
    
    # Check authorized_keys
    if [[ ! -f "/home/$TEST_USER/.ssh/authorized_keys" ]]; then
        log_error "Authorized keys file not found"
        ((errors++))
    fi
    
    # Check sshd-go binary
    if [[ ! -x "$PROJECT_ROOT/sshd" ]]; then
        log_error "sshd-go binary not found or not executable"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_error "Setup verification failed with $errors error(s)"
        exit 1
    fi
    
    log_info "Setup verification passed"
}

test_connection() {
    log_info "Testing SSH connection..."
    
    # Check if server is running
    if ! nc -z localhost $SSHD_GO_PORT 2>/dev/null; then
        log_warn "sshd-go server not running on port $SSHD_GO_PORT"
        log_info "Start server with: sudo ./sshd -D -p $SSHD_GO_PORT"
        return
    fi
    
    # Test connection
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=5 -p $SSHD_GO_PORT -i "$TEST_KEY_PATH" \
           "$TEST_USER@localhost" "echo 'Connection successful'" 2>/dev/null; then
        log_info "SSH connection test passed"
    else
        log_error "SSH connection test failed"
        log_info "Check server logs for details"
    fi
}

cleanup() {
    log_info "Cleaning up test environment..."
    
    # Remove test user
    if id "$TEST_USER" &>/dev/null; then
        userdel -r "$TEST_USER" 2>/dev/null || true
        log_info "Test user $TEST_USER removed"
    fi
    
    # Remove test keys
    if [[ -d "$SCRIPT_DIR/testdata" ]]; then
        rm -rf "$SCRIPT_DIR/testdata"
        log_info "Test keys removed"
    fi
    
    # Remove binary
    if [[ -f "$PROJECT_ROOT/sshd" ]]; then
        rm "$PROJECT_ROOT/sshd"
        log_info "sshd-go binary removed"
    fi
    
    log_info "Cleanup complete"
}

show_usage() {
    cat <<EOF
sshd-go Performance Benchmark Setup

This script prepares the environment for running performance benchmarks.

USAGE:
    sudo $0 [command]

COMMANDS:
    setup       Full setup (default)
    clean       Remove test environment
    verify      Verify setup without changes
    test        Test SSH connection
    help        Show this help message

SETUP STEPS:
    1. Create test SSH key pair
    2. Create test user with authorized key
    3. Build sshd-go binary
    4. Verify setup

AFTER SETUP:
    1. Start sshd-go test server:
       sudo ./sshd -D -p $SSHD_GO_PORT
    
    2. Run benchmarks:
       cd test && go test -bench=. -benchtime=3s

    3. For detailed analysis:
       go test -bench=. -benchtime=10s -benchmem

CLEANUP:
    sudo $0 clean

EOF
}

main() {
    local command="${1:-setup}"
    
    case "$command" in
        setup)
            check_root
            check_dependencies
            create_test_key
            create_test_user
            build_sshd_go
            verify_setup
            log_info "Setup complete!"
            log_info "Next steps:"
            log_info "  1. Start server: sudo $PROJECT_ROOT/sshd -D -p $SSHD_GO_PORT"
            log_info "  2. Run benchmarks: cd test && go test -bench=."
            ;;
        clean)
            check_root
            cleanup
            ;;
        verify)
            check_root
            verify_setup
            ;;
        test)
            test_connection
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
