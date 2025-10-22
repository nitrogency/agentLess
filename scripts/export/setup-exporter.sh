#!/bin/bash
set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common libraries
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/config.sh"

# Setup cleanup and interrupt handling
setup_cleanup_trap
setup_interrupt_trap "setup-exporter.sh"

# Get project root
PROJECT_ROOT="$(get_repo_root)"

# Installation paths
INSTALL_DIR="/opt/agentless"
BIN_DIR="$INSTALL_DIR/bin"
OUTPUT_DIR="/var/log/agentless-export"
STATE_DIR="/var/lib/agentless"
STATE_FILE="$STATE_DIR/exporter.state"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    log_error "This script must be run as root"
    exit 1
fi

# Step 1: Build the exporter
log_progress "[1/6] Building exporter..."
cd "$PROJECT_ROOT"

if ! command -v go &> /dev/null; then
    log_error "Go is not installed"
    exit 1
fi

# Build the exporter
log_info "Building cmd/exporter..."
go build -o "$BIN_DIR/exporter" cmd/exporter/main.go

if [ ! -f "$BIN_DIR/exporter" ]; then
    log_error "Failed to build exporter"
    exit 1
fi

chmod +x "$BIN_DIR/exporter"
log_success "Exporter built successfully"

# Step 2: Create output and state directories
log_progress "[2/6] Creating directories..."
mkdir -p "$OUTPUT_DIR"
mkdir -p "$STATE_DIR"
chmod 755 "$OUTPUT_DIR"
chmod 755 "$STATE_DIR"
log_success "Directories created"

# Step 3: Configure environment variables
log_progress "[3/6] Configuring environment..."

ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    log_error ".env file not found at $ENV_FILE"
    log_info "Please run setup.sh first to install the application."
    exit 1
fi

# Add export configuration to .env if not present
if ! grep -q "EXPORT_OUTPUT_DIR" "$ENV_FILE"; then
    echo "" >> "$ENV_FILE"
    echo "# Export Configuration" >> "$ENV_FILE"
    echo "EXPORT_OUTPUT_DIR=$OUTPUT_DIR" >> "$ENV_FILE"
    echo "EXPORT_STATE_FILE=$STATE_FILE" >> "$ENV_FILE"
    echo "EXPORT_BATCH_SIZE=1000" >> "$ENV_FILE"
    echo "EXPORT_MAX_FILE_SIZE=10485760  # 10MB" >> "$ENV_FILE"
    echo "EXPORT_INCLUDE_RAW_LOG=true" >> "$ENV_FILE"
    echo "EXPORT_DEVICE_INFO=true" >> "$ENV_FILE"
    log_success "Export configuration added to .env"
else
    log_info "Export configuration already present in .env"
fi

# Step 4: Install systemd units
log_progress "[4/6] Installing systemd units..."

# Copy systemd files
cp "$PROJECT_ROOT/scripts/systemd/agentless-exporter.service" /etc/systemd/system/
cp "$PROJECT_ROOT/scripts/systemd/agentless-exporter.timer" /etc/systemd/system/

# Reload systemd
systemctl daemon-reload
log_success "Systemd units installed"

# Step 5: Enable and start timer
log_progress "[5/6] Enabling export timer..."

systemctl enable agentless-exporter.timer
systemctl start agentless-exporter.timer

log_success "Export timer enabled and started"

# Step 6: Test the exporter
log_progress "[6/6] Testing exporter..."

# Run a dry-run test
if "$BIN_DIR/exporter" -config "$ENV_FILE" -dry-run -verbose 2>&1 | head -20; then
    log_success "Exporter test successful"
else
    log_warn "Test run produced errors (this may be normal if no logs exist yet)"
fi


log_section "Exporter Setup Complete"

log_info "${COLOR_BLUE}Configuration:${COLOR_RESET}"
log_info "  Output Directory: $OUTPUT_DIR"
log_info "  State File: $STATE_FILE"
log_info "  Export Interval: Every 5 minutes"
echo ""
log_info "${COLOR_BLUE}Management Commands:${COLOR_RESET}"
log_info "  View timer status:    systemctl status agentless-exporter.timer"
log_info "  View service status:  systemctl status agentless-exporter.service"
log_info "  View logs:            journalctl -u agentless-exporter -f"
log_info "  Manual export:        systemctl start agentless-exporter.service"
log_info "  Disable timer:        systemctl stop agentless-exporter.timer"
echo ""
log_info "${COLOR_BLUE}Log Files:${COLOR_RESET}"
log_info "  Export directory:     $OUTPUT_DIR"
log_info "  Log format:          JSON Lines (*.jsonl)"
log_info "  File pattern:        agentless-audit-YYYY-MM-DD-HH.jsonl"
echo ""
log_info "${COLOR_YELLOW}Next Steps:${COLOR_RESET}"
log_info "1. Configure your log ingestion tool to read from $OUTPUT_DIR/*.jsonl"
log_info "2. Adjust export interval by editing:"
log_info "   /etc/systemd/system/agentless-exporter.timer"
log_info "   Then run: systemctl daemon-reload && systemctl restart agentless-exporter.timer"
