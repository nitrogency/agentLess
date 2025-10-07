#!/bin/bash
#
# start-monitoring.sh - Unified monitoring launcher
# Detects device OS type and launches appropriate monitoring script
#
# Usage: start-monitoring.sh -d <device_id>
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

PROJECT_ROOT="$(get_repo_root)"
DB_PATH="$PROJECT_ROOT/$(get_config db_path)"

DEVICE_ID=""

show_usage() {
    log_error "Usage: $0 -d <device_id>"
    exit 2
}

while getopts ":d:" opt; do
  case "$opt" in
    d) DEVICE_ID="$OPTARG" ;;
    *) show_usage ;;
  esac
done

# Validate required parameters
if [[ -z "$DEVICE_ID" ]]; then
  show_usage
fi

log_info "Starting monitoring for device ID: $DEVICE_ID"

# Query device information from database
DEVICE_INFO=$(execute_sqlite "SELECT ip_address || '|' || ssh_user || '|' || ssh_key_path || '|' || ssh_port || '|' || COALESCE(os_type, 'linux') || '|' || name FROM devices WHERE id = $DEVICE_ID;" "$DB_PATH")

if [ -z "$DEVICE_INFO" ]; then
    log_error "Device not found in database: ID $DEVICE_ID"
    exit 1
fi

# Parse device information (format: ip|user|key|port|os_type|name)
IFS='|' read -r IP SSH_USER SSH_KEY_PATH SSH_PORT OS_TYPE DEVICE_NAME <<< "$DEVICE_INFO"

log_info "Device: $DEVICE_NAME"
log_info "IP: $IP"
log_info "User: $SSH_USER"
log_info "OS Type: $OS_TYPE"
log_info "Port: $SSH_PORT"

# Validate required fields
if [[ -z "$IP" || -z "$SSH_USER" || -z "$SSH_KEY_PATH" ]]; then
    log_error "Incomplete device configuration in database"
    exit 1
fi

# Launch appropriate monitoring script based on OS type
case "$OS_TYPE" in
    linux)
        log_info "Launching Linux audit log monitoring..."
        exec "$SCRIPT_DIR/linux/monitoring.sh" \
            -d "$DEVICE_ID" \
            -u "$SSH_USER" \
            -i "$IP" \
            -k "$SSH_KEY_PATH" \
            -p "$SSH_PORT"
        ;;
    
    windows)
        log_info "Launching Windows Sysmon monitoring..."
        exec "$SCRIPT_DIR/windows/monitoring-windows.sh" \
            -d "$DEVICE_ID" \
            -u "$SSH_USER" \
            -i "$IP" \
            -k "$SSH_KEY_PATH" \
            -p "$SSH_PORT"
        ;;
    
    *)
        log_error "Unknown OS type: $OS_TYPE (supported: linux, windows)"
        exit 1
        ;;
esac
