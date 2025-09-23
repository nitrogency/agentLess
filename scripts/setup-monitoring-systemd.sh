#!/bin/bash
#
# setup-monitoring-systemd.sh
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="$REPO_ROOT/data/site.db"
ENV_DIR="/etc/agentless"
UNIT_PATH="/etc/systemd/system/agentless-monitor@.service"
MONITOR_SH="$REPO_ROOT/scripts/monitoring.sh"

# Load .env for DB_ENCRYPTION_KEY if present
if [ -f "$REPO_ROOT/.env" ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$REPO_ROOT/.env" | xargs) || true
fi

# Check dependencies
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need sqlcipher
need systemctl

DB_KEY="${DB_ENCRYPTION_KEY:-default-dev-encryption-key-do-not-use-in-production}"

# Ensure required files/dirs
if [ ! -f "$MONITOR_SH" ]; then
  echo "Error: monitoring script not found: $MONITOR_SH" >&2
  exit 1
fi

if [ ! -f "$DB_PATH" ]; then
  echo "Warning: database not found at $DB_PATH (will still proceed if created later)" >&2
fi

# Query devices: id|ip|ssh_user|ssh_key_path|ssh_port
echo "Reading devices from DB..."
DEVICES=$(sqlcipher "$DB_PATH" "PRAGMA key = '$DB_KEY'; SELECT id, ip_address, ssh_user, ssh_key_path, COALESCE(ssh_port,'22') FROM devices WHERE status != 'deleted';" 2>/dev/null | grep -v '^ok$' || true)
if [ -z "$DEVICES" ]; then
  echo "No devices found. Add devices to the DB first." >&2
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
        echo "Removing stale device $did"
        sudo systemctl disable --now "agentless-monitor@$did.service" >/dev/null 2>&1 || true
        sudo systemctl reset-failed "agentless-monitor@$did.service" >/dev/null 2>&1 || true
        sudo rm -f -- "$envf"
        ;;
    esac
  done
fi

# Create env dir
if [ ! -d "$ENV_DIR" ]; then
  sudo mkdir -p "$ENV_DIR"
  sudo chmod 0750 "$ENV_DIR"
fi

# Install or update the unit template with absolute paths
UNIT_CONTENT="[Unit]
Description=AgentLess IDS Monitor for device %%i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
EnvironmentFile=%s/monitor-%%i.env
ExecStart=/usr/bin/env bash -lc '%s -d %%i -u "\$SSH_USER" -i "\$IP" -k "\$SSH_KEY" -p "\$SSH_PORT"'
Restart=always
RestartSec=2
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
"
# shellcheck disable=SC2059
printf "$UNIT_CONTENT" "$REPO_ROOT" "$ENV_DIR" "$MONITOR_SH" | sudo tee "$UNIT_PATH" >/dev/null

sudo systemctl daemon-reload

# Create per-device env and enable services
IFS=$'\n'
for row in $DEVICES; do
  IFS='|' read -r ID IP SSH_USER SSH_KEY SSH_PORT <<<"$row"
  if [ -z "$ID" ] || [ -z "$IP" ]; then
    echo "Skipping invalid row: $row" >&2
    continue
  fi
  [ -z "${SSH_USER:-}" ] && SSH_USER="monitor"
  [ -z "${SSH_KEY:-}" ] && SSH_KEY="$HOME/.ssh/ids_monitoring_key"
  [ -z "${SSH_PORT:-}" ] && SSH_PORT="22"

  ENV_FILE="$ENV_DIR/monitor-$ID.env"
  echo "Writing $ENV_FILE"
  sudo bash -c "cat > '$ENV_FILE' <<EOF
SSH_USER=$SSH_USER
IP=$IP
SSH_KEY=$SSH_KEY
SSH_PORT=$SSH_PORT
EOF"
  sudo chmod 0640 "$ENV_FILE"

  echo "Enabling and starting service: agentless-monitor@$ID"
  sudo systemctl enable --now "agentless-monitor@$ID.service"

done

# Show status summary
echo
systemctl list-units --type=service --state=running | grep -E 'agentless-monitor@' || true

echo "Done. Services installed: agentless-monitor@<device-id>.service"
