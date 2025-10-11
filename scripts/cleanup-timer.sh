#!/bin/bash
# cleanup-timer.sh [retention_days]
# Installs a systemd oneshot service + timer to purge old audit logs daily.
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Setup cleanup trap
setup_cleanup_trap

# Configuration
RETENTION_DAYS="${1:-$(get_config retention_days)}"
REPO_ROOT="$(get_repo_root)"
SERVICE_PATH="$SYSTEMD_SYSTEM_DIR/$CLEANUP_SERVICE"
TIMER_PATH="$SYSTEMD_SYSTEM_DIR/$CLEANUP_TIMER"

# Validate configuration
log_info "Retention period: $RETENTION_DAYS days"
log_info "Repository root: $REPO_ROOT"

# Check dependencies
check_dependency systemctl
check_dependency sudo

# Create service
log_progress "Creating systemd service: $CLEANUP_SERVICE"
sudo bash -c "cat > '$SERVICE_PATH' <<EOF
[Unit]
Description=Agent< - Cleanup old audit logs
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$REPO_ROOT
ExecStart=/usr/bin/env bash -lc '$REPO_ROOT/scripts/clean.sh $RETENTION_DAYS'
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF"

# Create timer
log_progress "Creating systemd timer: $CLEANUP_TIMER"
sudo bash -c "cat > '$TIMER_PATH' <<EOF
[Unit]
Description=Runs audit log cleanup daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF"

# Reload systemd and enable timer
log_progress "Enabling and starting cleanup timer"
systemctl_safe reload
systemctl_safe enable-start "$CLEANUP_TIMER"

log_success "Cleanup timer installed successfully!"
log_info "Timer status:"
systemctl list-timers | grep agentless-cleanup || log_warn "Timer not found in list"
