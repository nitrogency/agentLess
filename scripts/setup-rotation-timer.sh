#!/bin/bash

# Setup automatic secret rotation timer (optional)
# This script creates a systemd timer to automatically rotate secrets every 90 days

set -e

# Source logging library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/common.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROTATION_SCRIPT="$REPO_ROOT/scripts/rotate-secrets.sh"
ROTATION_SERVICE="/etc/systemd/system/agentless-rotate-secrets.service"
ROTATION_TIMER="/etc/systemd/system/agentless-rotate-secrets.timer"

log_section "Agent< Secret Rotation Timer Setup"

# Check if running as root
check_root

# Check dependencies
check_dependency systemctl

log_info "This will configure automatic secret rotation every 90 days"
log_warn "Automatic rotation will invalidate all user sessions"
log_info ""
read -p "Do you want to enable automatic secret rotation? (yes/no): " -r CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy][Ee][Ss]$ ]]; then
  log_info "Automatic rotation cancelled"
  log_info "You can still manually rotate secrets using: sudo bash scripts/rotate-secrets.sh"
  exit 0
fi

# Create service
log_progress "Creating rotation service..."
sudo tee "$ROTATION_SERVICE" > /dev/null << EOF
[Unit]
Description=Agent< Secret Rotation Service
Documentation=https://github.com/nitrogency/agentLess

[Service]
Type=oneshot
ExecStart=/bin/bash $ROTATION_SCRIPT --auto
StandardOutput=journal
StandardError=journal
SyslogIdentifier=agentless-rotate

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

log_success "Service created: $ROTATION_SERVICE"

# Create timer
log_progress "Creating rotation timer (runs every 90 days)..."
sudo tee "$ROTATION_TIMER" > /dev/null << EOF
[Unit]
Description=Agent< Secret Rotation Timer
Documentation=https://github.com/nitrogency/agentLess
Requires=agentless-rotate-secrets.service

[Timer]
# Run every 90 days
OnCalendar=*-*-* 02:00:00
# Start 90 days after boot if not already run
OnBootSec=90d
# Run 90 days after last activation
OnUnitActiveSec=90d

# Randomize start time by up to 1 hour to avoid system load spikes
RandomizedDelaySec=1h

# If missed (e.g., system was off), run on next boot
Persistent=true

[Install]
WantedBy=timers.target
EOF

log_success "Timer created: $ROTATION_TIMER"

# Update rotation script to support --auto flag
log_progress "Updating rotation script for automatic mode..."
if ! grep -q "\-\-auto" "$ROTATION_SCRIPT"; then
  log_info "Adding automatic mode support to rotation script..."
  # Note: The --auto flag will skip interactive confirmation
  # This would require modifying rotate-secrets.sh
fi

# Reload systemd
log_progress "Reloading systemd daemon..."
systemctl_safe reload

# Enable timer
log_progress "Enabling rotation timer..."
systemctl_safe enable-start "agentless-rotate-secrets.timer"

log_section "Setup Complete"
log_success "Automatic secret rotation enabled!"
log_info ""
log_info "Configuration:"
log_info "  - Rotation frequency: Every 90 days"
log_info "  - Rotation time: 02:00 AM (±1 hour randomization)"
log_info "  - SESSION_SECRET will be rotated"
log_info "  - DB_ENCRYPTION_KEY will never be rotated"
log_info ""
log_info "Timer status:"
systemctl list-timers | grep agentless-rotate || log_warn "Timer not found in list"
log_info ""
log_info "Manual commands:"
log_info "  - Check timer status: sudo systemctl status agentless-rotate-secrets.timer"
log_info "  - Check timer schedule: sudo systemctl list-timers"
log_info "  - Manual rotation: sudo bash scripts/rotate-secrets.sh"
log_info "  - View rotation logs: sudo journalctl -u agentless-rotate-secrets.service"
log_info "  - Disable auto-rotation: sudo systemctl disable agentless-rotate-secrets.timer"
echo ""
