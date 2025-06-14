#!/bin/bash
#
# IDS Monitoring Cron Setup Script
# This script sets up a cron job to run the monitoring script every 5 minutes
#

set -e

# Configuration
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
MONITORING_SCRIPT="$SCRIPT_DIR/monitoring.sh"
CRON_FILE="/tmp/ids_monitoring_cron"
LOG_DIR="/var/log/ids"
DB_PATH="$SCRIPT_DIR/../data/site.db"

# Check if the monitoring script exists
if [ ! -f "$MONITORING_SCRIPT" ]; then
    echo "Error: Monitoring script not found at $MONITORING_SCRIPT"
    exit 1
fi

# Make sure the monitoring script is executable
chmod +x "$MONITORING_SCRIPT"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Get all devices from the database
echo "Retrieving devices from the database..."
DEVICES=$(sqlite3 "$DB_PATH" "SELECT id, ip_address, ssh_user, ssh_key_path, ssh_port FROM devices WHERE status != 'deleted';")

if [ -z "$DEVICES" ]; then
    echo "No devices found in the database. Please add devices first."
    exit 1
fi

# Create cron job entries for each device
echo "" > "$CRON_FILE"  # Clear the file

while IFS="|" read -r id ip_address ssh_user ssh_key_path ssh_port; do
    # Use default port 22 if not specified
    if [ -z "$ssh_port" ]; then
        ssh_port="22"
    fi
    
    # Use default SSH key if not specified
    if [ -z "$ssh_key_path" ]; then
        ssh_key_path="/home/$(whoami)/.ssh/ids_monitoring_key"
    fi
    
    # Use default SSH user if not specified
    if [ -z "$ssh_user" ]; then
        ssh_user="monitor"
    fi
    
    echo "Adding cron job for device $id ($ip_address)..."
    echo "*/5 * * * * cd $(dirname $SCRIPT_DIR) && $MONITORING_SCRIPT -u $ssh_user -i $ip_address -k $ssh_key_path -p $ssh_port > $LOG_DIR/monitoring_${id}.log 2>&1" >> "$CRON_FILE"
done <<< "$DEVICES"

# Install the cron job
echo "Setting up cron jobs to run monitoring script every 5 minutes..."
crontab -l 2>/dev/null | grep -v "$MONITORING_SCRIPT" | cat - "$CRON_FILE" | crontab -

# Clean up
rm -f "$CRON_FILE"

echo "✅ Cron jobs set up successfully!"
echo "The monitoring script will run every 5 minutes for each registered device."
echo "Logs will be written to $LOG_DIR/monitoring_<device_id>.log"

# Display current cron jobs
echo -e "\nCurrent cron jobs:"
crontab -l | grep -v "^#"
