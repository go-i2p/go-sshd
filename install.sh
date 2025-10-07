#!/bin/bash
set -euo pipefail

# sshd-go Installation Script
# This script installs sshd-go as a systemd service

PROGRAM_NAME="sshd-go"
BINARY_NAME="sshd"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/default}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if binary exists
check_binary() {
    if [[ ! -f "./${BINARY_NAME}" ]]; then
        log_error "Binary './${BINARY_NAME}' not found in current directory"
        log_info "Please run 'go build -o ${BINARY_NAME} cmd/sshd/main.go' first"
        exit 1
    fi
}

# Backup existing OpenSSH configuration if it exists
backup_openssh() {
    if systemctl is-active --quiet sshd; then
        log_warn "OpenSSH sshd is currently running"
        read -p "Do you want to stop and disable OpenSSH sshd? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Stopping and disabling OpenSSH sshd..."
            systemctl stop sshd
            systemctl disable sshd
            log_success "OpenSSH sshd stopped and disabled"
        else
            log_warn "Installation continuing with OpenSSH sshd still active"
            log_warn "Make sure to configure different ports to avoid conflicts"
        fi
    fi
}

# Install binary
install_binary() {
    log_info "Installing ${PROGRAM_NAME} binary to ${INSTALL_PREFIX}/sbin/${PROGRAM_NAME}"
    
    # Create sbin directory if it doesn't exist
    mkdir -p "${INSTALL_PREFIX}/sbin"
    
    # Copy binary with proper permissions
    cp "./${BINARY_NAME}" "${INSTALL_PREFIX}/sbin/${PROGRAM_NAME}"
    chmod 755 "${INSTALL_PREFIX}/sbin/${PROGRAM_NAME}"
    
    log_success "Binary installed successfully"
}

# Install systemd files
install_systemd_files() {
    log_info "Installing systemd service files to ${SYSTEMD_DIR}"
    
    # Copy systemd files
    cp "systemd/${PROGRAM_NAME}.service" "${SYSTEMD_DIR}/"
    cp "systemd/${PROGRAM_NAME}.socket" "${SYSTEMD_DIR}/"
    cp "systemd/${PROGRAM_NAME}@.service" "${SYSTEMD_DIR}/"
    cp "systemd/${PROGRAM_NAME}-keygen.service" "${SYSTEMD_DIR}/"
    
    # Copy default configuration
    cp "systemd/${PROGRAM_NAME}.default" "${CONFIG_DIR}/${PROGRAM_NAME}"
    
    # Set proper permissions
    chmod 644 "${SYSTEMD_DIR}/${PROGRAM_NAME}."*
    chmod 644 "${CONFIG_DIR}/${PROGRAM_NAME}"
    
    log_success "Systemd files installed successfully"
}

# Reload systemd and enable service
configure_systemd() {
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    read -p "Do you want to enable ${PROGRAM_NAME} service on boot? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        log_info "Enabling ${PROGRAM_NAME} service..."
        systemctl enable "${PROGRAM_NAME}.service"
        log_success "${PROGRAM_NAME} service enabled"
    fi
    
    read -p "Do you want to start ${PROGRAM_NAME} service now? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        log_info "Starting ${PROGRAM_NAME} service..."
        systemctl start "${PROGRAM_NAME}.service"
        
        # Check if service started successfully
        if systemctl is-active --quiet "${PROGRAM_NAME}.service"; then
            log_success "${PROGRAM_NAME} service started successfully"
            log_info "Service status:"
            systemctl status "${PROGRAM_NAME}.service" --no-pager -l
        else
            log_error "Failed to start ${PROGRAM_NAME} service"
            log_info "Check logs with: journalctl -u ${PROGRAM_NAME}.service"
            return 1
        fi
    fi
}

# Show next steps
show_next_steps() {
    echo
    log_success "Installation completed!"
    echo
    log_info "Next steps:"
    echo "  1. Configure SSH settings in /etc/ssh/sshd_config"
    echo "  2. Test configuration: ${INSTALL_PREFIX}/sbin/${PROGRAM_NAME} -t"
    echo "  3. Manage service: systemctl {start|stop|restart|status} ${PROGRAM_NAME}"
    echo "  4. View logs: journalctl -u ${PROGRAM_NAME}.service"
    echo "  5. Edit startup options: /etc/default/${PROGRAM_NAME}"
    echo
    log_info "For socket activation mode (alternative to service mode):"
    echo "  systemctl enable ${PROGRAM_NAME}.socket"
    echo "  systemctl start ${PROGRAM_NAME}.socket"
    echo
}

# Main installation function
main() {
    log_info "Starting ${PROGRAM_NAME} installation..."
    
    check_root
    check_binary
    
    # Confirm installation
    echo
    log_info "This will install ${PROGRAM_NAME} to:"
    echo "  Binary: ${INSTALL_PREFIX}/sbin/${PROGRAM_NAME}"
    echo "  Systemd files: ${SYSTEMD_DIR}/"
    echo "  Configuration: ${CONFIG_DIR}/${PROGRAM_NAME}"
    echo
    read -p "Continue with installation? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
    
    backup_openssh
    install_binary
    install_systemd_files
    configure_systemd
    show_next_steps
}

# Handle script arguments
case "${1:-install}" in
    install)
        main
        ;;
    uninstall)
        log_info "Uninstalling ${PROGRAM_NAME}..."
        systemctl stop "${PROGRAM_NAME}.service" 2>/dev/null || true
        systemctl disable "${PROGRAM_NAME}.service" 2>/dev/null || true
        rm -f "${INSTALL_PREFIX}/sbin/${PROGRAM_NAME}"
        rm -f "${SYSTEMD_DIR}/${PROGRAM_NAME}."*
        rm -f "${CONFIG_DIR}/${PROGRAM_NAME}"
        systemctl daemon-reload
        log_success "${PROGRAM_NAME} uninstalled successfully"
        ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        echo "  install   - Install ${PROGRAM_NAME} (default)"
        echo "  uninstall - Remove ${PROGRAM_NAME}"
        exit 1
        ;;
esac