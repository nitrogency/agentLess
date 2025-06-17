#!/bin/bash
#
# IDS Monitoring Cron Setup Script
# This script sets up a cron job to run the monitoring script every 5 minutes
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../data/site.db"
MONITORING_SCRIPT="$SCRIPT_DIR/monitoring.sh"
CRON_FILE="/tmp/monitoring_cron_jobs.tmp"

# Load environment variables from .env file if it exists
if [ -f "$SCRIPT_DIR/../.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/../.env" | xargs)
fi

# Get database encryption key
get_db_encryption_key() {
    if [ -n "$DB_ENCRYPTION_KEY" ]; then
        echo "$DB_ENCRYPTION_KEY"
    else
        # Use default development key (matches the Go application)
        echo "default-dev-encryption-key-do-not-use-in-production"
    fi
}

# Function to execute SQLite commands with encryption
execute_sqlite() {
    local query="$1"
    local db_key=$(get_db_encryption_key)
    
    # Check if sqlcipher is installed
    if ! command -v sqlcipher &> /dev/null; then
        echo "Error: sqlcipher is not installed. Please install it with:"
        echo "  sudo apt update && sudo apt install -y sqlcipher"
        exit 1
    fi
    
    # Use SQLCipher with the encryption key
    # Suppress output for INSERT/UPDATE operations, preserve for SELECT
    if [[ "$query" =~ ^[[:space:]]*(INSERT|UPDATE|DELETE) ]]; then
        sqlcipher "$DB_PATH" "PRAGMA key = '$db_key'; $query" > /dev/null 2>&1
    else
        # For SELECT queries, filter out the 'ok' output
        sqlcipher "$DB_PATH" "PRAGMA key = '$db_key'; $query" 2>/dev/null | grep -v '^ok$'
    fi
}

# Check if the monitoring script exists
if [ ! -f "$MONITORING_SCRIPT" ]; then
    echo "Error: Monitoring script not found at $MONITORING_SCRIPT"
    exit 1
fi

# Make sure the monitoring script is executable
chmod +x "$MONITORING_SCRIPT"

# Get all devices from the database including random_user flag and setup_user
echo "Retrieving devices from the database..."
DEVICES=$(execute_sqlite "SELECT id, ip_address, ssh_user, ssh_key_path, ssh_port, random_user, setup_user FROM devices WHERE status != 'deleted';")

if [ -z "$DEVICES" ]; then
    echo "No devices found in the database. Please add devices first."
    exit 1
fi

# Create cron job entries for each device
echo "" > "$CRON_FILE"  # Clear the file

while IFS="|" read -r id ip_address ssh_user ssh_key_path ssh_port random_user setup_user; do
    # Use default port 22 if not specified
    if [ -z "$ssh_port" ]; then
        ssh_port="22"
    fi
    
    # Use default SSH key if not specified
    if [ -z "$ssh_key_path" ]; then
        ssh_key_path="/home/$(whoami)/.ssh/ids_monitoring_key"
    fi
    
    # Check if random_user is enabled (1) and use setup_user instead
    if [ "$random_user" = "1" ] && [ -n "$setup_user" ]; then
        ssh_user="$setup_user"
        echo "Using random user '$setup_user' for device $id ($ip_address)"
    # Use default SSH user if not specified
    elif [ -z "$ssh_user" ]; then
        ssh_user="monitor"
    fi
    
    echo "Adding cron job for device $id ($ip_address)..."
    # Create cron job with full paths and environment setup
    echo "*/5 * * * * cd '$SCRIPT_DIR/..' && export PATH=\$PATH:/usr/bin:/bin && '$MONITORING_SCRIPT' -u '$ssh_user' -i '$ip_address' -k '$ssh_key_path' -p '$ssh_port'" >> "$CRON_FILE"
done <<< "$DEVICES"

# Install the cron job
echo "Setting up cron jobs to run monitoring script every 5 minutes..."
crontab -l 2>/dev/null | grep -v "$MONITORING_SCRIPT" | cat - "$CRON_FILE" | crontab -

# Clean up
rm -f "$CRON_FILE"

echo "✅ Cron jobs set up successfully!"

# Verify the cron jobs were installed
echo ""
echo "📋 Installed cron jobs:"
crontab -l 2>/dev/null | grep "$MONITORING_SCRIPT" || echo "⚠️  No monitoring cron jobs found!"

# Show summary
DEVICE_COUNT=$(echo "$DEVICES" | wc -l)
echo ""
echo "📊 Summary:"
echo "  • $DEVICE_COUNT devices configured for monitoring"
echo "  • Monitoring runs every 5 minutes"
echo "  • Database: $DB_PATH"

echo ""
echo "🔍 To test the setup:"
echo "  ./test_cron_monitoring.sh"
echo ""
echo "📝 To monitor status:"
echo "  Check database: ./check_audit_logs.sh"
echo "  System logs: journalctl -f | grep monitoring"

# Display current cron jobs
echo -e "\nCurrent cron jobs:"
crontab -l | grep -v "^#"
