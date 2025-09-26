#!/bin/bash
#
# setup-monitoring.sh
# Create and enable one systemd service per device to run continuous monitoring.
# Keeps it as simple as possible and self-contained.
#
# This script:
#  1) Reads devices from the encrypted SQLite DB (SQLCipher)
#  2) Creates per-device environment files with SSH parameters
#  3) Installs a template unit agentless-monitor@.service pointing to scripts/monitoring.sh
#  4) Enables and starts agentless-monitor@<device-id>.service for each device
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
ENV_DIR="$AGENTLESS_ENV_DIR"
UNIT_PATH="$SYSTEMD_SYSTEM_DIR/$MONITOR_SERVICE_TEMPLATE"
MONITOR_SH="$REPO_ROOT/scripts/monitoring.sh"

# Check dependencies
check_dependency sqlcipher
check_dependency systemctl

log_info "Repository: $REPO_ROOT"
log_info "Database: $DB_PATH" 
log_info "Environment dir: $ENV_DIR"
log_info "Monitor script: $MONITOR_SH"

# Ensure required files/dirs
if [ ! -f "$MONITOR_SH" ]; then
  handle_error "monitoring script not found: $MONITOR_SH"
fi

if [ ! -f "$DB_PATH" ]; then
  handle_error "database not found: $DB_PATH"
fi

# Query devices: id|ip|ssh_user|ssh_key_path|ssh_port
log_progress "Reading devices from database..."
DEVICES=$(execute_sqlite "SELECT id, ip_address, ssh_user, ssh_key_path, COALESCE(ssh_port,'22') FROM devices WHERE status != 'deleted';" "$DB_PATH")
if [ -z "$DEVICES" ]; then
  log_warn "No devices found. Add devices to the DB first."
  # Still proceed to reconcile and stop any stale services
fi

# Build a space-delimited list of active IDs for reconciliation like: " 1 2 3 "
ACTIVE_IDS=""
if [ -n "$DEVICES" ]; then
  IFS=$'\n'
  for row in $DEVICES; do
    IFS='|' read -r ID _rest <<<"$row"
    if [ -n "$ID" ]; then
      ACTIVE_IDS+=" $ID"
    fi
  done
fi
ACTIVE_IDS="${ACTIVE_IDS# }"

# Reconcile: disable/stop units and remove env files for IDs not in DB
echo "Reconciling stale monitor units/env files..."
if ls "$ENV_DIR"/monitor-*.env >/dev/null 2>&1; then
  for envf in "$ENV_DIR"/monitor-*.env; do
    [ -e "$envf" ] || continue
    bn=$(basename "$envf")
    did=${bn#monitor-}
    did=${did%.env}
    case " $ACTIVE_IDS " in
      *" $did "*)
        # still active
        :
        ;;
      *)
        log_info "Removing stale device $did"
        systemctl_safe disable-stop "agentless-monitor@$did.service"
        sudo_command rm -f -- "$envf"
        ;;
    esac
  done
fi

# Create env dir
log_progress "Setting up environment directory..."
if [ ! -d "$ENV_DIR" ]; then
  sudo_command mkdir -p "$ENV_DIR"
  sudo_command chmod 0750 "$ENV_DIR"
fi

# Install or update the unit template with absolute paths
UNIT_CONTENT="[Unit]
Description=Agent< Monitor for Device %%i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=%s/monitor-%%i.env
Environment=HOME=/root
ExecStart=%s -d %%i -u \${SSH_USER} -i \${IP} -k \${SSH_KEY} -p \${SSH_PORT}
Restart=always
RestartSec=2
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
printf "$UNIT_CONTENT" "$REPO_ROOT" "$ENV_DIR" "$MONITOR_SH" "$REPO_ROOT" | sudo_command tee "$UNIT_PATH" >/dev/null

systemctl_safe reload

# Create per-device env and enable services
IFS=$'\n'
for row in $DEVICES; do
  IFS='|' read -r ID IP SSH_USER SSH_KEY SSH_PORT <<<"$row"
  if [ -z "$ID" ] || [ -z "$IP" ]; then
    log_warn "Skipping invalid row: $row"
    continue
  fi
  [ -z "${SSH_USER:-}" ] && SSH_USER="$(get_config remote_user)"
  [ -z "${SSH_KEY:-}" ] && SSH_KEY="$(get_config ssh_key_path)"
  [ -z "${SSH_PORT:-}" ] && SSH_PORT="$(get_config ssh_port)"

  ENV_FILE="$ENV_DIR/monitor-$ID.env"
  log_progress "Configuring device $ID ($IP)..."
  sudo_command bash -c "cat > '$ENV_FILE' <<ENVEOF
SSH_USER=$SSH_USER
IP=$IP
SSH_KEY=$SSH_KEY
SSH_PORT=$SSH_PORT
ENVEOF"
  sudo_command chmod 0640 "$ENV_FILE"

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
