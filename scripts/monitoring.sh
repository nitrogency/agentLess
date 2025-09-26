#!/bin/bash
#
# monitoring.sh - minimal collector to feed audit lines into scripts/monitoring.go
#
# Usage: monitoring.sh -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> -p <port>
# Notes: keeps it simple on purpose; relies on Go program to classify and insert into DB.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."
GO_MONITOR="$PROJECT_ROOT/scripts/monitoring.go"
BIN_MONITOR="$PROJECT_ROOT/bin/monitor"

DEVICE_ID=""
SSH_USER=""
IP=""
KEY=""
PORT="22"

while getopts ":d:u:i:k:p:" opt; do
  case "$opt" in
    d) DEVICE_ID="$OPTARG" ;;
    u) SSH_USER="$OPTARG" ;;
    i) IP="$OPTARG" ;;
    k) KEY="$OPTARG" ;;
    p) PORT="$OPTARG" ;;
    *) echo "Usage: $0 -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> [-p <port>]" >&2; exit 2 ;;
  esac
done

if [[ -z "$DEVICE_ID" || -z "$SSH_USER" || -z "$IP" || -z "$KEY" ]]; then
  echo "Usage: $0 -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> [-p <port>]" >&2
  exit 2
fi

# SSH options (lean, with compression + timeouts)
SSH_OPTS=(
  -i "$KEY"
  -p "$PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=3
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=2
  -o Compression=yes
)

# Remote command: try tail (preferred), fallback to sudo tail, then cat
REMOTE_CMD='if [ -r /var/log/audit/audit.log ]; then tail -n 1000 -F /var/log/audit/audit.log; \
else sudo -n tail -n 1000 -F /var/log/audit/audit.log 2>/dev/null || sudo tail -n 1000 -F /var/log/audit/audit.log; fi'

# Pipe raw audit lines into Go program which writes directly to the encrypted DB
# Prefer compiled binary under systemd (Go may not be in PATH); fallback to go run.
if [ -x "$BIN_MONITOR" ]; then
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "$REMOTE_CMD" | \
    (cd "$PROJECT_ROOT" && "$BIN_MONITOR" -device "$DEVICE_ID")
else
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "$REMOTE_CMD" | \
    (cd "$PROJECT_ROOT" && go run ./scripts/monitoring.go -device "$DEVICE_ID")
fi
