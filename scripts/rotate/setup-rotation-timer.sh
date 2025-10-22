#!/bin/bash

# Setup automatic secret rotation timer (optional)
# This script creates a systemd timer to automatically rotate secrets every 90 days

set -e

# Source logging library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Setup cleanup and interrupt handling
setup_cleanup_trap
setup_interrupt_trap "setup-rotation-timer.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROTATION_SCRIPT="$REPO_ROOT/scripts/rotate/rotate-secrets.sh"
ROTATION_SERVICE="/etc/systemd/system/agentless-rotate-secrets.service"
ROTATION_TIMER="/etc/systemd/system/agentless-rotate-secrets.timer"

log_section "Agent< Secret Rotation Timer Setup"

# Check if running as root
check_root

# Check dependencies
check_dependency systemctl

log_info "This will configure automatic secret rotation every 90 days"
log_warn "Automatic rotation will invalidate all user sessions"
echo ""
read -p "Do you want to enable automatic secret rotation? (yes/no): " -r CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy][Ee][Ss]$ ]]; then
  log_info "Automatic rotation cancelled"
  log_info "You can still manually rotate secrets using: sudo bash scripts/rotate/rotate-secrets.sh"
  exit 0
fi

# Create service from template
log_progress "Creating rotation service..."
SERVICE_TEMPLATE="$REPO_ROOT/systemd/agentless-rotate-secrets.service.template"
if [ ! -f "$SERVICE_TEMPLATE" ]; then
  echo "Error: Template file not found: $SERVICE_TEMPLATE"
  exit 1
fi

# Substitute variables in template and install service file
sed -e "s|__ROTATION_SCRIPT__|$ROTATION_SCRIPT|g" \
    "$SERVICE_TEMPLATE" | sudo tee "$ROTATION_SERVICE" > /dev/null

log_success "Service created: $ROTATION_SERVICE"

# Create timer from template
log_progress "Creating rotation timer (runs every 90 days)..."
TIMER_TEMPLATE="$REPO_ROOT/systemd/agentless-rotate-secrets.timer"
if [ ! -f "$TIMER_TEMPLATE" ]; then
  echo "Error: Template file not found: $TIMER_TEMPLATE"
  exit 1
fi

# Copy timer file (no substitution needed)
sudo cp "$TIMER_TEMPLATE" "$ROTATION_TIMER"

log_success "Timer created: $ROTATION_TIMER"

# Update rotation script to support --auto flag
log_progress "Updating rotation script for automatic mode..."
if ! grep -q "\-\-auto" "$ROTATION_SCRIPT"; then
  log_info "Adding automatic mode support to rotation script..."
fi

# Reload systemd
log_progress "Reloading systemd daemon..."
systemctl_safe reload

# Enable timer
log_progress "Enabling rotation timer..."
systemctl_safe enable-start "agentless-rotate-secrets.timer"

log_section "Setup Complete"
log_success "Automatic secret rotation enabled!"
echo ""
log_info "Configuration:"
log_info "  - Rotation frequency: Every 90 days"
log_info "  - Rotation time: 02:00 AM (±1 hour randomization)"
log_info "  - SESSION_SECRET will be rotated"
log_info "  - DB_ENCRYPTION_KEY will never be rotated"
echo ""
log_info "Timer status:"
systemctl list-timers | grep agentless-rotate || log_warn "Timer not found in list"
echo ""
log_info "Manual commands:"
log_info "  - Check timer status: sudo systemctl status agentless-rotate-secrets.timer"
log_info "  - Check timer schedule: sudo systemctl list-timers"
  log_info "  - Manual rotation: sudo bash scripts/rotate/rotate-secrets.sh"
log_info "  - View rotation logs: sudo journalctl -u agentless-rotate-secrets.service"
log_info "  - Disable auto-rotation: sudo systemctl disable agentless-rotate-secrets.timer"
echo ""
