#!/bin/bash
#
# setup-monitoring.sh
# Create and enable one systemd service per device to run continuous monitoring.
# Uses database as single source of truth for device configuration.
#
# This script:
#  1) Reads active devices from the encrypted SQLite DB (SQLCipher)
#  2) Installs a template unit agentless-monitor@.service pointing to scripts/start-monitoring.sh
#  3) Enables and starts agentless-monitor@<device-id>.service for each device
#  4) Reconciles and removes services for deleted devices
#
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Setup cleanup trap
setup_cleanup_trap

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
  # Still proceed to reconcile and stop any stale services
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

# Install or update the unit template with absolute paths
UNIT_CONTENT="[Unit]
Description=AgentLess Monitor for Device %%i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
Environment=HOME=/root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=%s -d %%i
Restart=always
RestartSec=10
# Hardening (relaxed for script execution)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%s
ProtectHome=false
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service @network-io

[Install]
WantedBy=multi-user.target
"
log_progress "Installing systemd service template..."
# shellcheck disable=SC2059
printf "$UNIT_CONTENT" "$REPO_ROOT" "$MONITOR_SH" "$REPO_ROOT" | sudo_command tee "$UNIT_PATH" >/dev/null

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
log_section "Log Cleanup Timer Setup"
log_progress "Setting up cleanup timer for log retention..."
CLEANUP_SCRIPT="$SCRIPT_DIR/cleanup-timer.sh"
if [ -f "$CLEANUP_SCRIPT" ]; then
    bash "$CLEANUP_SCRIPT" "$(get_config retention_days)"
    log_success "Cleanup timer installed successfully."
else
    log_warn "cleanup-timer.sh not found at $CLEANUP_SCRIPT"
    log_info "You may need to set up log cleanup manually."
fi
