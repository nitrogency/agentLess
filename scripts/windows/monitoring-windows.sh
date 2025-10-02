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

# PowerShell command to export Sysmon events in XML format
# We use Get-WinEvent to query Sysmon logs and export as XML
REMOTE_CMD='powershell -Command "
\$lastRecordId = 0;
\$logFile = \"\$env:TEMP\\sysmon-last-record.txt\";

# Load last record ID if exists
if (Test-Path \$logFile) {
    try {
        \$lastRecordId = [int](Get-Content \$logFile -ErrorAction SilentlyContinue);
    } catch {
        \$lastRecordId = 0;
    }
}

# Query Sysmon events newer than last record ID
try {
    \$filter = @{
        LogName = \"Microsoft-Windows-Sysmon/Operational\";
        StartTime = (Get-Date).AddMinutes(-10);
    };
    
    if (\$lastRecordId -gt 0) {
        # Get events with RecordId greater than last processed
        \$events = Get-WinEvent -FilterHashtable \$filter -ErrorAction SilentlyContinue | 
                   Where-Object { \$_.RecordId -gt \$lastRecordId } |
                   Sort-Object RecordId;
    } else {
        # First run, get recent events
        \$events = Get-WinEvent -FilterHashtable \$filter -MaxEvents 1000 -ErrorAction SilentlyContinue |
                   Sort-Object RecordId;
    }
    
    if (\$events) {
        # Export events as XML
        foreach (\$event in \$events) {
            \$event.ToXml();
            \$lastRecordId = \$event.RecordId;
        }
        
        # Save last record ID
        \$lastRecordId | Out-File -FilePath \$logFile -Force;
    }
} catch {
    Write-Error \"Error querying Sysmon logs: \$_\";
    exit 1;
}
"'

log_debug "Remote PowerShell command configured"

# Function to collect logs once (for interval-based collection)
collect_logs_once() {
    log_debug "Collecting Sysmon logs from $IP..."
    
    # Execute remote command and pipe to Go parser
    if [ -x "$BIN_MONITOR_WIN" ]; then
        log_debug "Using compiled Windows monitor binary: $BIN_MONITOR_WIN"
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "$REMOTE_CMD" 2>/dev/null | \
            (cd "$PROJECT_ROOT" && "$BIN_MONITOR_WIN" -device "$DEVICE_ID")
    else
        log_debug "Using go run with source: $GO_MONITOR"
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$IP" "$REMOTE_CMD" 2>/dev/null | \
            (cd "$PROJECT_ROOT" && go run ./scripts/windows/monitoring-windows.go -device "$DEVICE_ID")
    fi
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        log_debug "Successfully collected Sysmon logs"
    else
        log_error "Failed to collect Sysmon logs (exit code: $exit_code)"
    fi
    
    return $exit_code
}

# Run collection loop with intervals (easier to implement than real-time streaming)
# Windows event logs are better suited to polling rather than real-time streaming
COLLECTION_INTERVAL=$(get_config "windows_collection_interval" 30)

log_info "Starting Sysmon log collection with ${COLLECTION_INTERVAL}s interval"

while true; do
    collect_logs_once
    
    # Wait before next collection
    sleep "$COLLECTION_INTERVAL"
done
