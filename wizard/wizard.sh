#!/bin/bash
# Clauditor Installation Wizard
# Interactive installer for the security audit watchdog
#
# Usage:
#   ./wizard.sh [--dry-run] [--uninstall]
#
# Options:
#   --dry-run    Show commands without executing
#   --uninstall  Remove all components

set -euo pipefail

# Configuration
STEALTH_USER="sysaudit"
STEALTH_BINARY="/usr/local/sbin/systemd-journaldd"
STEALTH_SENTINEL="/usr/local/sbin/systemd-core-check"
CONFIG_DIR="/etc/sysaudit"
LOG_DIR="/var/lib/.sysd/.audit"
UNIT_DIR="/etc/systemd/system"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
UNINSTALL=false
for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            ;;
        --uninstall)
            UNINSTALL=true
            ;;
    esac
done

# Helper functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }

run_cmd() {
    local cmd="$1"
    echo -e "${YELLOW}  \$ ${cmd}${NC}"
    if [[ "$DRY_RUN" == "false" ]]; then
        eval "$cmd"
    fi
}

confirm() {
    local prompt="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would prompt: $prompt"
        return 0
    fi
    read -p "$prompt [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Check prerequisites
check_prereqs() {
    info "Checking prerequisites..."
    
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
    
    if ! command -v systemctl &>/dev/null; then
        error "systemd is required"
    fi
    
    # Check for chattr support
    if ! command -v chattr &>/dev/null; then
        warn "chattr not found - append-only protection unavailable"
    fi
    
    success "Prerequisites OK"
}

# Find repo root
find_repo_root() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(dirname "$script_dir")"
    
    if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
        error "Cannot find repo root (expected Cargo.toml at $REPO_ROOT)"
    fi
    
    info "Repo root: $REPO_ROOT"
}

# Build release binary
build_binary() {
    info "Building release binary..."
    
    if [[ ! -f "$REPO_ROOT/target/release/clauditor" ]]; then
        run_cmd "cd '$REPO_ROOT' && cargo build --release"
    else
        info "Binary already built, skipping"
    fi
    
    success "Binary ready"
}

# Uninstall function
do_uninstall() {
    info "=== UNINSTALL MODE ==="
    warn "This will remove all clauditor components"
    
    echo
    echo "Commands to execute:"
    echo "===================="
    
    echo
    info "Step 1: Stop and disable services"
    run_cmd "systemctl stop systemd-journaldd.service systemd-core-check.path systemd-core-check.timer 2>/dev/null || true"
    run_cmd "systemctl disable systemd-journaldd.service systemd-core-check.path systemd-core-check.timer 2>/dev/null || true"
    
    echo
    info "Step 2: Remove append-only attribute from logs"
    run_cmd "chattr -a '$LOG_DIR'/* 2>/dev/null || true"
    
    echo
    info "Step 3: Remove unit files"
    run_cmd "rm -f '$UNIT_DIR'/systemd-journaldd*.service '$UNIT_DIR'/systemd-journaldd*.timer"
    run_cmd "rm -f '$UNIT_DIR'/systemd-core-check.{path,timer,service}"
    run_cmd "systemctl daemon-reload"
    
    echo
    info "Step 4: Remove binaries"
    run_cmd "rm -f '$STEALTH_BINARY' '$STEALTH_SENTINEL'"
    
    echo
    info "Step 5: Remove config and logs"
    run_cmd "rm -rf '$CONFIG_DIR'"
    run_cmd "rm -rf '$LOG_DIR'"
    
    echo
    info "Step 6: Remove user"
    run_cmd "userdel '$STEALTH_USER' 2>/dev/null || true"
    
    success "Uninstall complete"
}

# Main installation
do_install() {
    info "=== CLAUDITOR INSTALLATION WIZARD ==="
    echo
    info "This wizard will install the security audit watchdog."
    info "All commands will be shown before execution."
    echo
    
    # Step 1: Create user
    echo
    info "Step 1: Create system user '$STEALTH_USER'"
    if id "$STEALTH_USER" &>/dev/null; then
        info "User already exists, skipping"
    else
        run_cmd "useradd --system --shell /usr/sbin/nologin --no-create-home '$STEALTH_USER'"
    fi
    
    # Step 2: Create directories
    echo
    info "Step 2: Create directories"
    run_cmd "install -d -m 0750 -o root -g root '$CONFIG_DIR'"
    run_cmd "install -d -m 0750 -o root -g root '$LOG_DIR'"
    
    # Step 3: Generate HMAC key
    echo
    info "Step 3: Generate HMAC key"
    if [[ -f "$CONFIG_DIR/key" ]]; then
        info "Key already exists, skipping"
    else
        run_cmd "head -c 32 /dev/urandom | xxd -p > '$CONFIG_DIR/key'"
        run_cmd "chmod 0440 '$CONFIG_DIR/key'"
        run_cmd "chown root:'$STEALTH_USER' '$CONFIG_DIR/key'"
    fi
    
    # Step 4: Install binaries
    echo
    info "Step 4: Install binaries"
    build_binary
    run_cmd "install -m 0755 -o root -g root '$REPO_ROOT/target/release/clauditor' '$STEALTH_BINARY'"
    run_cmd "install -m 0755 -o root -g root '$REPO_ROOT/dist/bin/systemd-core-check' '$STEALTH_SENTINEL'"
    
    # Step 5: Store binary checksum
    echo
    info "Step 5: Store binary checksum for sentinel"
    run_cmd "sha256sum '$STEALTH_BINARY' | awk '{print \$1}' > '$CONFIG_DIR/binary.sha256'"
    
    # Step 6: Create config
    echo
    info "Step 6: Create config file"
    if [[ -f "$CONFIG_DIR/config.toml" ]]; then
        info "Config already exists, skipping"
    else
        cat > /tmp/clauditor-config.toml << 'CONFIGEOF'
# Clauditor configuration

[collector]
# Watch paths (workspace directories to monitor)
watch_paths = ["/home/clawdbot"]
# Target UID to monitor (clawdbot user)
target_uid = 1000

[writer]
log_path = "/var/lib/.sysd/.audit/events.log"
fsync = "periodic"
fsync_interval = 100
max_size_bytes = 104857600  # 100MB

[alerter]
min_severity = "medium"
queue_path = "/var/lib/.sysd/.audit/alerts.queue"

[[alerter.channels]]
type = "clawdbot_wake"

[[alerter.channels]]
type = "syslog"
facility = "local0"
CONFIGEOF
        run_cmd "install -m 0640 -o root -g '$STEALTH_USER' /tmp/clauditor-config.toml '$CONFIG_DIR/config.toml'"
        run_cmd "rm /tmp/clauditor-config.toml"
    fi
    
    # Step 7: Install unit files
    echo
    info "Step 7: Install systemd unit files"
    run_cmd "install -m 0644 -o root -g root '$REPO_ROOT/dist/systemd/'*.service '$UNIT_DIR/'"
    run_cmd "install -m 0644 -o root -g root '$REPO_ROOT/dist/systemd/'*.timer '$UNIT_DIR/'"
    run_cmd "install -m 0644 -o root -g root '$REPO_ROOT/dist/systemd/'*.path '$UNIT_DIR/'"
    
    # Step 8: Create initial log file with append-only
    echo
    info "Step 8: Create log file with append-only attribute"
    run_cmd "touch '$LOG_DIR/events.log'"
    run_cmd "chown '$STEALTH_USER':'$STEALTH_USER' '$LOG_DIR/events.log'"
    run_cmd "chmod 0640 '$LOG_DIR/events.log'"
    if command -v chattr &>/dev/null; then
        run_cmd "chattr +a '$LOG_DIR/events.log'"
        success "Append-only attribute set"
    else
        warn "chattr not available - skipping append-only"
    fi
    
    # Step 9: Reload and enable services
    echo
    info "Step 9: Enable and start services"
    run_cmd "systemctl daemon-reload"
    run_cmd "systemctl enable systemd-journaldd.service"
    run_cmd "systemctl enable systemd-journaldd-digest.timer"
    run_cmd "systemctl enable systemd-core-check.path"
    run_cmd "systemctl enable systemd-core-check.timer"
    run_cmd "systemctl start systemd-journaldd.service"
    run_cmd "systemctl start systemd-journaldd-digest.timer"
    run_cmd "systemctl start systemd-core-check.path"
    run_cmd "systemctl start systemd-core-check.timer"
    
    # Verify
    echo
    info "Step 10: Verify installation"
    run_cmd "systemctl --no-pager status systemd-journaldd.service"
    
    echo
    success "=== INSTALLATION COMPLETE ==="
    echo
    info "Services installed:"
    echo "  - systemd-journaldd.service (main daemon)"
    echo "  - systemd-journaldd-digest.timer (daily reports)"
    echo "  - systemd-core-check.path (file change detection)"
    echo "  - systemd-core-check.timer (periodic integrity checks)"
    echo
    info "Logs: $LOG_DIR/events.log"
    info "Config: $CONFIG_DIR/config.toml"
    info "Digests: $LOG_DIR/digest-*.md"
    echo
    info "To uninstall: $0 --uninstall"
}

# Main
main() {
    echo
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║           CLAUDITOR INSTALLATION WIZARD               ║"
    echo "║       Security Audit Watchdog for Clawdbot            ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo
    
    if [[ "$DRY_RUN" == "true" ]]; then
        warn "DRY-RUN MODE: Commands will be shown but not executed"
        echo
    fi
    
    check_prereqs
    find_repo_root
    
    if [[ "$UNINSTALL" == "true" ]]; then
        if confirm "Are you sure you want to uninstall clauditor?"; then
            do_uninstall
        else
            info "Uninstall cancelled"
        fi
    else
        echo
        echo "The following actions will be performed:"
        echo "  1. Create system user: $STEALTH_USER"
        echo "  2. Create directories: $CONFIG_DIR, $LOG_DIR"
        echo "  3. Generate HMAC key for tamper detection"
        echo "  4. Install binaries to /usr/local/sbin/"
        echo "  5. Install systemd units"
        echo "  6. Enable and start services"
        echo
        
        if confirm "Proceed with installation?"; then
            do_install
        else
            info "Installation cancelled"
        fi
    fi
}

main "$@"
