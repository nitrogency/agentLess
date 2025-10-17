#!/bin/bash
#
# monitoring.sh - minimal collector to feed audit lines into scripts/linux/monitoring.go
#
# Usage: monitoring.sh -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> -p <port>
# Notes: keeps it simple on purpose; relies on Go program to classify and insert into DB.
set -euo pipefail

# Source shared libraries (minimal logging for this
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Load database encryption key and export for Go binary
if [ -f "/etc/agentless/secrets.env" ]; then
    # shellcheck disable=SC1091
    source /etc/agentless/secrets.env
    export DB_ENCRYPTION_KEY
fi

# Configuration
PROJECT_ROOT="$(get_repo_root)"
GO_MONITOR="$PROJECT_ROOT/scripts/linux/monitoring.go"
BIN_MONITOR="$PROJECT_ROOT/bin/monitor"
DEVICE_ID=""
SSH_USER=""
IP=""
KEY=""
PORT="$(get_config ssh_port)"

show_usage() {
    log_error "Usage: $0 -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> [-p <port>]"
    exit 2
}

while getopts ":d:u:i:k:p:" opt; do
  case "$opt" in
    d) DEVICE_ID="$OPTARG" ;;
    u) SSH_USER="$OPTARG" ;;
    i) IP="$OPTARG" ;;
    k) KEY="$OPTARG" ;;
    p) PORT="$OPTARG" ;;
    *) show_usage ;;
  esac
done

# Validate required parameters
if [[ -z "$DEVICE_ID" || -z "$SSH_USER" || -z "$IP" || -z "$KEY" ]]; then
  show_usage
fi

# Validate inputs
if ! validate_ip "$IP"; then
    handle_error "Invalid IP address: $IP"
fi

if ! validate_ssh_key "$KEY"; then
    handle_error "Invalid or missing SSH key: $KEY"
fi

if ! validate_username "$SSH_USER"; then
    handle_error "Invalid username: $SSH_USER"
fi

# SSH options (using config defaults with overrides)
SSH_OPTS=(
  -i "$KEY"
  -p "$PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout="$(get_config ssh_connect_timeout)"
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=2
  -o Compression=yes
)

# Remote command: try tail (preferred), fallback to sudo tail, then cat  
LOG_LIMIT="$(get_config log_limit)"

REMOTE_CMD="(
  if [ -r $AUDIT_LOG_PATH ]; then
    tail -n $LOG_LIMIT -F $AUDIT_LOG_PATH
  else
    sudo -n tail -n $LOG_LIMIT -F $AUDIT_LOG_PATH 2>/dev/null || \
    sudo tail -n $LOG_LIMIT -F $AUDIT_LOG_PATH
  fi
) & (
  if [ -r $CLAMAV_LOG_PATH ]; then
    tail -n $LOG_LIMIT -F $CLAMAV_LOG_PATH
  else
    sudo -n tail -n $LOG_LIMIT -F $CLAMAV_LOG_PATH 2>/dev/null || \
    sudo tail -n $LOG_LIMIT -F $CLAMAV_LOG_PATH
  fi
); wait"

log_debug "Starting monitoring for device $DEVICE_ID ($SSH_USER@$IP:$PORT)"
log_debug "SSH options: ${SSH_OPTS[*]}"
log_debug "Remote command: $REMOTE_CMD"

# Pipe raw audit lines into Go program which writes directly to the encrypted DB
if [ -x "$BIN_MONITOR" ]; then
  log_debug "Using compiled monitor binary: $BIN_MONITOR"
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "$REMOTE_CMD" 2>&1 | \
    (cd "$PROJECT_ROOT" && "$BIN_MONITOR" -device "$DEVICE_ID" 2>&1)
elif [ -f "$BIN_MONITOR" ]; then
  log_error "Binary exists but is not executable: $BIN_MONITOR"
  log_info "Run: chmod +x $BIN_MONITOR"
  exit 1
else
  log_error "Compiled binary not found: $BIN_MONITOR"
  log_info "Run: go build -o $BIN_MONITOR ./scripts/linux/monitoring.go"
  exit 1
fi
