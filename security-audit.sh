#!/usr/bin/env bash
#
# Security Audit Script for go-sshd
# Runs multiple security scanning tools to detect vulnerabilities in dependencies
#
# Usage: ./security-audit.sh [options]
#
# Options:
#   --install    Install required security scanning tools
#   --quick      Quick scan (govulncheck only)
#   --full       Full scan (all tools)
#   --ci         CI mode (non-interactive, fail on vulnerabilities)
#   --help       Show this help message
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
RESULTS_DIR="$PROJECT_ROOT/.security-audit"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Flags
CI_MODE=false
QUICK_SCAN=false
FULL_SCAN=false
INSTALL_TOOLS=false

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print usage
usage() {
    cat << EOF
Security Audit Script for go-sshd

Usage: $0 [options]

Options:
    --install    Install required security scanning tools
    --quick      Quick scan (govulncheck only)
    --full       Full scan (all tools)
    --ci         CI mode (non-interactive, fail on vulnerabilities)
    --help       Show this help message

Examples:
    $0 --install              # Install scanning tools
    $0 --quick                # Run quick vulnerability scan
    $0 --full                 # Run comprehensive security audit
    $0 --ci                   # CI mode for automated pipelines

EOF
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install security scanning tools
install_tools() {
    log_info "Installing security scanning tools..."
    
    # Install govulncheck (official Go vulnerability checker)
    if ! command_exists govulncheck; then
        log_info "Installing govulncheck..."
        go install golang.org/x/vuln/cmd/govulncheck@latest
        log_success "govulncheck installed"
    else
        log_info "govulncheck already installed"
    fi
    
    # Install nancy (OSS Index scanner) - optional
    if ! command_exists nancy; then
        log_info "Installing nancy..."
        go install github.com/sonatype-nexus-community/nancy@latest
        log_success "nancy installed"
    else
        log_info "nancy already installed"
    fi
    
    # Check for trivy (recommended but requires separate installation)
    if ! command_exists trivy; then
        log_warning "trivy not found. Install from: https://aquasecurity.github.io/trivy/"
        log_info "  For Ubuntu/Debian: sudo apt-get install trivy"
        log_info "  For macOS: brew install trivy"
    else
        log_info "trivy already installed"
    fi
    
    log_success "Tool installation complete"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results will be saved to: $RESULTS_DIR"
}

# Run govulncheck (official Go vulnerability scanner)
run_govulncheck() {
    log_info "Running govulncheck (official Go vulnerability database)..."
    
    local result_file="$RESULTS_DIR/govulncheck_${TIMESTAMP}.txt"
    local exit_code=0
    
    if command_exists govulncheck; then
        if govulncheck ./... 2>&1 | tee "$result_file"; then
            log_success "govulncheck: No vulnerabilities found"
        else
            exit_code=$?
            log_error "govulncheck: Vulnerabilities detected (see $result_file)"
            return $exit_code
        fi
    else
        log_warning "govulncheck not installed. Run with --install to install tools."
        return 1
    fi
    
    return 0
}

# Run nancy (Sonatype OSS Index scanner)
run_nancy() {
    log_info "Running nancy (Sonatype OSS Index scanner)..."
    
    local result_file="$RESULTS_DIR/nancy_${TIMESTAMP}.txt"
    local exit_code=0
    
    if command_exists nancy; then
        if go list -json -deps ./... | nancy sleuth 2>&1 | tee "$result_file"; then
            log_success "nancy: No vulnerabilities found"
        else
            exit_code=$?
            log_error "nancy: Vulnerabilities detected (see $result_file)"
            return $exit_code
        fi
    else
        log_warning "nancy not installed. Run with --install to install tools."
        return 0  # Don't fail if nancy is not installed (optional tool)
    fi
    
    return 0
}

# Run trivy filesystem scanner
run_trivy() {
    log_info "Running trivy (comprehensive vulnerability scanner)..."
    
    local result_file="$RESULTS_DIR/trivy_${TIMESTAMP}.txt"
    local exit_code=0
    
    if command_exists trivy; then
        if trivy fs --severity HIGH,CRITICAL "$PROJECT_ROOT" 2>&1 | tee "$result_file"; then
            log_success "trivy: No HIGH or CRITICAL vulnerabilities found"
        else
            exit_code=$?
            log_error "trivy: Vulnerabilities detected (see $result_file)"
            return $exit_code
        fi
    else
        log_warning "trivy not installed. Install from: https://aquasecurity.github.io/trivy/"
        return 0  # Don't fail if trivy is not installed (optional tool)
    fi
    
    return 0
}

# Check for outdated dependencies
check_outdated() {
    log_info "Checking for outdated dependencies..."
    
    local result_file="$RESULTS_DIR/outdated_${TIMESTAMP}.txt"
    
    log_info "Current dependencies:"
    go list -m -u all 2>&1 | tee "$result_file"
    
    # Check if any dependencies have updates available
    if go list -m -u all | grep -q '\[.*\]'; then
        log_warning "Some dependencies have updates available"
        log_info "Run 'go get -u ./...' to update dependencies"
    else
        log_success "All dependencies are up to date"
    fi
}

# Generate dependency list
generate_sbom() {
    log_info "Generating Software Bill of Materials (SBOM)..."
    
    local sbom_file="$RESULTS_DIR/sbom_${TIMESTAMP}.json"
    
    go list -json -deps ./... > "$sbom_file"
    log_success "SBOM generated: $sbom_file"
    
    # Print summary
    local dep_count=$(go list -deps ./... | wc -l)
    log_info "Total dependencies: $dep_count"
}

# Run all security checks
run_full_scan() {
    log_info "Starting comprehensive security audit..."
    local overall_status=0
    
    # Run govulncheck (critical)
    if ! run_govulncheck; then
        overall_status=1
    fi
    
    # Run nancy (optional)
    run_nancy || true
    
    # Run trivy (optional)
    run_trivy || true
    
    # Check for outdated dependencies
    check_outdated
    
    # Generate SBOM
    generate_sbom
    
    return $overall_status
}

# Quick scan (govulncheck only)
run_quick_scan() {
    log_info "Starting quick vulnerability scan..."
    run_govulncheck
}

# Generate report
generate_report() {
    local status=$1
    local report_file="$RESULTS_DIR/report_${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Security Audit Report
Generated: $(date)
Project: go-sshd
Status: $([ $status -eq 0 ] && echo "PASS" || echo "FAIL")

Scan Results:
-------------
$(ls -1 "$RESULTS_DIR"/*_${TIMESTAMP}.txt 2>/dev/null || echo "No detailed results available")

Summary:
--------
$([ $status -eq 0 ] && echo "✅ No vulnerabilities detected" || echo "❌ Vulnerabilities detected - review results above")

Next Steps:
-----------
1. Review detailed scan results in $RESULTS_DIR
2. Update vulnerable dependencies: go get -u <package>
3. Run tests after updates: go test ./...
4. Re-run security audit: $0 --full

EOF
    
    cat "$report_file"
    log_info "Full report saved to: $report_file"
}

# Main function
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                INSTALL_TOOLS=true
                shift
                ;;
            --quick)
                QUICK_SCAN=true
                shift
                ;;
            --full)
                FULL_SCAN=true
                shift
                ;;
            --ci)
                CI_MODE=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Default to quick scan if no mode specified
    if ! $INSTALL_TOOLS && ! $QUICK_SCAN && ! $FULL_SCAN; then
        QUICK_SCAN=true
    fi
    
    # Install tools if requested
    if $INSTALL_TOOLS; then
        install_tools
        exit 0
    fi
    
    # Setup results directory
    setup_results_dir
    
    # Run appropriate scan
    local exit_code=0
    if $FULL_SCAN; then
        if ! run_full_scan; then
            exit_code=1
        fi
    elif $QUICK_SCAN; then
        if ! run_quick_scan; then
            exit_code=1
        fi
    fi
    
    # Generate report
    echo ""
    generate_report $exit_code
    
    # CI mode: fail if vulnerabilities found
    if $CI_MODE && [ $exit_code -ne 0 ]; then
        log_error "CI mode: Security audit failed"
        exit 1
    fi
    
    # Final status
    echo ""
    if [ $exit_code -eq 0 ]; then
        log_success "Security audit completed successfully"
    else
        log_error "Security audit detected vulnerabilities"
    fi
    
    exit $exit_code
}

# Run main function
main "$@"
