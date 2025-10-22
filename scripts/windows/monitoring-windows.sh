#!/bin/bash
#
# monitoring-windows.sh - Sysmon log collector for Windows devices
#
# Usage: monitoring-windows.sh -d <device_id> -u <ssh_user> -i <ip> -k <ssh_key> -p <port>
# Collects Sysmon logs from Windows via SSH (OpenSSH for Windows)
set -euo pipefail

# Source shared libraries
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
GO_MONITOR="$PROJECT_ROOT/scripts/windows/monitoring-windows.go"
BIN_MONITOR_WIN="$PROJECT_ROOT/bin/monitor-windows"

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

log_debug "Received parameters:"
log_debug "  Device ID: $DEVICE_ID"
log_debug "  SSH User: $SSH_USER"
log_debug "  IP: $IP"
log_debug "  SSH Key: $KEY"
log_debug "  Port: $PORT"

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

# SSH options
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

log_debug "Starting Windows Sysmon monitoring for device $DEVICE_ID ($SSH_USER@$IP:$PORT)"
log_debug "SSH command: ssh ${SSH_OPTS[*]} $SSH_USER@$IP"
log_debug "SSH key file: $(ls -la \"$KEY\" 2>&1 || echo 'NOT FOUND')"

# PowerShell script content
read -r -d '' PS_SCRIPT << 'PSEOF' || true
$lastRecordId = 0
$logFile = "$env:TEMP\sysmon-last-record.txt"

if (Test-Path $logFile) {
    try {
        $lastRecordId = [int](Get-Content $logFile -ErrorAction SilentlyContinue)
    } catch {
        $lastRecordId = 0
    }
}

$filter = @{ LogName = "Microsoft-Windows-Sysmon/Operational" }

if ($lastRecordId -gt 0) {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | Where-Object { $_.RecordId -gt $lastRecordId } | Sort-Object RecordId
} else {
    $filter["StartTime"] = (Get-Date).AddHours(-1)
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 100 -ErrorAction SilentlyContinue | Sort-Object RecordId
}

if ($events) {
    foreach ($event in $events) {
        $event.ToXml()
        $lastRecordId = $event.RecordId
    }
} else {
    $latest = Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($latest) {
        $lastRecordId = $latest.RecordId
    }
}

if ($lastRecordId -gt 0) {
    $lastRecordId | Out-File -FilePath $logFile -Force
}
PSEOF

log_debug "PowerShell script configured"

# Function to collect logs once (for interval-based collection)
collect_logs_once() {
    log_debug "Collecting Sysmon logs from $IP..."
    
    # Execute remote command and pipe to Go parser
    # Use || true to prevent script exit on non-zero return (empty results)
    if [ -x "$BIN_MONITOR_WIN" ]; then
        log_debug "Using compiled Windows monitor binary: $BIN_MONITOR_WIN"
        # Pass PowerShell script via stdin to avoid quote escaping issues
        echo "$PS_SCRIPT" | ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" 'powershell -Command -' 2>&1 | \
            (cd "$PROJECT_ROOT" && "$BIN_MONITOR_WIN" -device "$DEVICE_ID" 2>&1) || true
    elif [ -f "$BIN_MONITOR_WIN" ]; then
        log_error "Binary exists but is not executable: $BIN_MONITOR_WIN"
        log_info "Run: chmod +x $BIN_MONITOR_WIN"
        exit 1
    else
        log_error "Compiled binary not found: $BIN_MONITOR_WIN"
        log_info "Run: go build -o $BIN_MONITOR_WIN ./scripts/windows/monitoring-windows.go"
        exit 1
    fi
    
    log_debug "Collection cycle completed"
    return 0
}

# Windows event logs are better suited to polling rather than real-time streaming
COLLECTION_INTERVAL=$(get_config "windows_collection_interval" 30)

log_info "Starting Sysmon log collection with ${COLLECTION_INTERVAL}s interval"

while true; do
    collect_logs_once
    
    # Wait before next collection
    sleep "$COLLECTION_INTERVAL"
done
