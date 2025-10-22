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

# Create service from template
log_progress "Creating systemd service: $CLEANUP_SERVICE"
SERVICE_TEMPLATE="$REPO_ROOT/systemd/agentless-cleanup.service.template"
if [ ! -f "$SERVICE_TEMPLATE" ]; then
  handle_error "Template file not found: $SERVICE_TEMPLATE"
fi

# Substitute variables in template and install service file
sed -e "s|__REPO_ROOT__|$REPO_ROOT|g" \
    -e "s|__RETENTION_DAYS__|$RETENTION_DAYS|g" \
    "$SERVICE_TEMPLATE" | sudo tee "$SERVICE_PATH" > /dev/null

# Create timer from template
log_progress "Creating systemd timer: $CLEANUP_TIMER"
TIMER_TEMPLATE="$REPO_ROOT/systemd/agentless-cleanup.timer"
if [ ! -f "$TIMER_TEMPLATE" ]; then
  handle_error "Template file not found: $TIMER_TEMPLATE"
fi

# Copy timer file (no substitution needed)
sudo cp "$TIMER_TEMPLATE" "$TIMER_PATH"

# Reload systemd and enable timer
log_progress "Enabling and starting cleanup timer"
systemctl_safe reload
systemctl_safe enable-start "$CLEANUP_TIMER"

log_success "Cleanup timer installed successfully!"
log_info "Timer status:"
systemctl list-timers | grep agentless-cleanup || log_warn "Timer not found in list"
