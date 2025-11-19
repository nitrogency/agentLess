#!/bin/bash
#
# setup-monitoring.sh
# Create and enable one systemd service per device to run continuous monitoring.
# Uses database as single source of truth for device configuration.
#
# This script:
#  1) Reads active devices from DB
#  2) Installs a template unit agentless-monitor@.service pointing to scripts/start-monitoring.sh
#  3) Enables and starts agentless-monitor@<device-id>.service for each device
#  4) Removes services for deleted devices
#
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Load database encryption key
if [ -f "/etc/agentless/secrets.env" ]; then
    # shellcheck disable=SC1091
    source /etc/agentless/secrets.env
fi

# Setup cleanup trap
setup_cleanup_trap

# Setup interrupt handling
setup_interrupt_trap "setup-monitoring.sh"

# Configuration
REPO_ROOT="$(get_repo_root)"
DB_PATH="$REPO_ROOT/$(get_config db_path)"
UNIT_PATH="$SYSTEMD_SYSTEM_DIR/$MONITOR_SERVICE_TEMPLATE"
MONITOR_SH="$REPO_ROOT/scripts/start-monitoring.sh"

# Check dependencies
check_dependency sqlcipher
check_dependency systemctl

log_info "Repository: $REPO_ROOT"
log_info "Database: $DB_PATH" 
log_info "Monitor script: $MONITOR_SH"

# Ensure required files/dirs
if [ ! -f "$MONITOR_SH" ]; then
  handle_error "monitoring script not found: $MONITOR_SH"
fi

if [ ! -f "$DB_PATH" ]; then
  handle_error "database not found: $DB_PATH"
fi

# Query active device IDs from database
log_progress "Reading devices from database..."
DEVICES=$(execute_sqlite "SELECT id, name FROM devices WHERE status != 'deleted';" "$DB_PATH")
if [ -z "$DEVICES" ]; then
  log_warn "No devices found. Add devices to the DB first."
fi

# Build a space-delimited list of active IDs for reconciliation
ACTIVE_IDS=""
if [ -n "$DEVICES" ]; then
  IFS=$'\n'
  for row in $DEVICES; do
    IFS='|' read -r ID NAME <<<"$row"
    if [ -n "$ID" ]; then
      ACTIVE_IDS+=" $ID"
    fi
  done
fi
ACTIVE_IDS="${ACTIVE_IDS# }"

# Reconcile: disable/stop units for IDs not in DB
log_progress "Reconciling stale monitor units..."
for service_file in $SYSTEMD_SYSTEM_DIR/agentless-monitor@*.service; do
  [ -e "$service_file" ] || continue
  
  # Extract device ID from service filename
  bn=$(basename "$service_file")
  did=${bn#agentless-monitor@}
  did=${did%.service}
  
  case " $ACTIVE_IDS " in
    *" $did "*)
      # still active
      :
      ;;
    *)
      log_info "Removing stale device service: $did"
      systemctl_safe disable-stop "agentless-monitor@$did.service"
      ;;
  esac
done

# Install or update the unit template from template file
TEMPLATE_FILE="$REPO_ROOT/scripts/systemd/agentless-monitor@.service.template"
if [ ! -f "$TEMPLATE_FILE" ]; then
  handle_error "Template file not found: $TEMPLATE_FILE"
fi

log_progress "Installing systemd service template..."
# Substitute variables in template and install service file
sed -e "s|__REPO_ROOT__|$REPO_ROOT|g" \
    -e "s|__MONITOR_SCRIPT__|$MONITOR_SH|g" \
    "$TEMPLATE_FILE" | sudo_command tee "$UNIT_PATH" >/dev/null

systemctl_safe reload

# Enable and start services for each device
IFS=$'\n'
for row in $DEVICES; do
  IFS='|' read -r ID NAME <<<"$row"
  if [ -z "$ID" ]; then
    log_warn "Skipping invalid row: $row"
    continue
  fi

  log_progress "Configuring device $ID ($NAME)..."
  log_info "Enabling and starting service: agentless-monitor@$ID"
  systemctl_safe enable-start "agentless-monitor@$ID.service"
done

systemctl list-units --type=service --state=running | grep -E 'agentless-monitor@' || log_info "No monitoring services currently running"

log_success "Monitoring services setup completed!"
log_info "Services installed: agentless-monitor@<device-id>.service"

# Set up cleanup timer for log retention
log_progress "Setting up cleanup timer for log retention..."
CLEANUP_SCRIPT="$SCRIPT_DIR/cleanup/cleanup-timer.sh"
if [ -f "$CLEANUP_SCRIPT" ]; then
    bash "$CLEANUP_SCRIPT" "$(get_config retention_days)"
    log_success "Cleanup timer installed successfully."
else
    log_warn "cleanup-timer.sh not found at $CLEANUP_SCRIPT"
    log_info "You may need to set up log cleanup manually."
fi
