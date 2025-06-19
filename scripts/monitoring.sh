#!/bin/bash
#
# IDS Monitoring Script - Simplified Version
# This script connects to a remote device, retrieves audit logs, and stores them in the database
#

set -e

# Function to determine security level based on audit key or log content
determine_security_level() {
    local log_text="$1"
    local log_text_lower=$(echo "$log_text" | tr '[:upper:]' '[:lower:]')
    
    # Decode proctitle if present for better command analysis
    local decoded_proctitle=""
    if echo "$log_text" | grep -q 'proctitle='; then
        local proctitle_hex=$(echo "$log_text" | grep -o 'proctitle=[^ ]*' | head -n 1 | cut -d= -f2)
        decoded_proctitle=$(echo "$proctitle_hex" | xxd -r -p 2>/dev/null | tr '\0' ' ' | sed 's/^ *//;s/ *$//' || echo "")
    fi
    
    # First try to extract audit key from the log
    local audit_key=$(echo "$log_text" | grep -o 'key="\?[a-zA-Z0-9_-]\+"\?' | sed 's/key="\?\([a-zA-Z0-9_-]\+\)"\?/\1/')
    
    # If we found an audit key, use it to determine security level
    if [ -n "$audit_key" ]; then
        # Enhanced monitoring script detection using decoded proctitle
        if [ -n "$decoded_proctitle" ]; then
            local proctitle_lower=$(echo "$decoded_proctitle" | tr '[:upper:]' '[:lower:]')
            
            # Check for monitoring activities in decoded command line
            if echo "$proctitle_lower" | grep -qE '(cat.*audit|tail.*audit|ssh.*audit|sudo.*cat.*audit|sudo.*tail.*audit)'; then
                echo "low"
                return
            fi
            
            # Check for SSH commands reading logs
            if echo "$proctitle_lower" | grep -qE 'ssh.*cat /var/log/audit|ssh.*tail /var/log/audit'; then
                echo "low"
                return
            fi
            
            # Check for monitoring script patterns
            if echo "$proctitle_lower" | grep -qE '(monitoring\.sh|ids.*monitor|audit.*collect)'; then
                echo "low"
                return
            fi
        fi
        
        # Check for monitoring script activities - always mark as low
        if echo "$log_text_lower" | grep -qE 'comm="(cat|ssh)"' && echo "$log_text_lower" | grep -qE '(audit\.log|/var/log/audit)'; then
            echo "low"
            return
        fi
        
        # Check for SSH connections reading audit logs (monitoring script activity)
        if echo "$log_text_lower" | grep -q 'comm="ssh"' && echo "$log_text_lower" | grep -qE '(cat.*audit|audit.*cat)'; then
            echo "low"
            return
        fi
        
        # Check for sudo cat operations on audit logs (monitoring script)
        if echo "$log_text_lower" | grep -q 'comm="sudo"' && echo "$log_text_lower" | grep -qE '(cat.*audit|audit.*cat)'; then
            echo "low"
            return
        fi
        
        # Check for ausearch operations and always mark them as low
        if echo "$log_text_lower" | grep -q 'comm="ausearch"'; then
            echo "low"
            return
        fi
        
        # Check for ausearch in arguments or command line
        if echo "$log_text_lower" | grep -E '(ausearch|/sbin/ausearch)' > /dev/null; then
            echo "low"
            return
        fi
        
        # Check for sudo running ausearch
        if echo "$log_text_lower" | grep -q 'comm="sudo"' && echo "$log_text_lower" | grep -E 'ausearch' > /dev/null; then
            echo "low"
            return
        fi
        
        # Check for dpkg operations and mark them as low
        if echo "$log_text_lower" | grep -q 'comm="dpkg"'; then
            echo "low"
            return
        fi
        
        # Check for systemd operations and mark them as low regardless of the key
        if echo "$log_text_lower" | grep -q 'comm="systemd"' || echo "$log_text_lower" | grep -E '(/systemd|systemd-)' > /dev/null; then
            # Even if the key is 'reconnaissance' or 'suspicious', systemd operations are normal
            echo "low"
            return
        fi
        
        # Check for common system processes accessing /proc files (often flagged as reconnaissance)
        if [ "$audit_key" = "reconnaissance" ]; then
            # Common system processes that legitimately access /proc
            if echo "$log_text_lower" | grep -qE 'comm="(systemd|cron|crond|sshd|bash|sh|snapd|networkd|networkmanager|apt|apt-get|dnf|yum|journald|rsyslogd|syslogd|logrotate|chronyd|ntpd|udevd|dbus-daemon|polkitd|accounts-daemon)"'; then
                echo "low"
                return
            fi
            
            # System paths that indicate legitimate system processes
            if echo "$log_text_lower" | grep -qE 'exe="(/usr/lib|/lib|/bin|/sbin|/usr/bin|/usr/sbin)/[^"]+"'; then
                echo "low"
                return
            fi
        fi
        
        # Special handling for audit_logs key - check if it's monitoring script activity
        if [ "$audit_key" = "audit_logs" ]; then
            # If it's cat or ssh reading audit logs, it's likely the monitoring script
            if echo "$log_text_lower" | grep -qE 'comm="(cat|ssh)"'; then
                echo "low"
                return
            fi
            
            # If it's accessing /var/log/audit/, it's likely legitimate monitoring
            if echo "$log_text_lower" | grep -qE '/var/log/audit'; then
                echo "low"
                return
            fi
        fi
        
        # High security keys - ONLY suspicious and reconnaissance commands
        local high_keys="suspicious|reconnaissance"
        
        # Medium security keys - security-relevant but not necessarily malicious
        local medium_keys="privilege_esc|user_pass|sudoers_change|authentication|failed_login|user_del|mac_policy|audit_tools|audit_logs|user_add|user_modification|group_add|group_modification|user_list|user_group|group_accounts|passwd_change|passwd_history|kernel_module|kernel_param|systemd_monitoring|startup_scripts|perm_mod|mount_operations"
        
        # Low security keys - normal system operations
        local low_keys="root_commands|user_list|user_group|group_accounts|time_change|net_environment_exe|cron_events|software_mgmt|user_delete_files|command_execution"
        
        # Check if the key matches high security keys
        if echo "$audit_key" | grep -E "$high_keys" > /dev/null; then
            # Additional check for suspicious commands - verify it's not a system process
            if [ "$audit_key" = "suspicious" ]; then
                # If it's a system process in /usr/sbin or similar, downgrade to medium
                if echo "$log_text_lower" | grep -E 'exe="/usr/(lib|sbin)' > /dev/null; then
                    echo "medium"
                    return
                fi
            fi
            echo "high"
            return
        fi
        
        # Check if the key matches medium security keys
        if echo "$audit_key" | grep -E "$medium_keys" > /dev/null; then
            echo "medium"
            return
        fi
        
        # Check if the key matches explicitly low security keys
        if echo "$audit_key" | grep -E "$low_keys" > /dev/null; then
            echo "low"
            return
        fi
        
        # All other keys are low security by default
        echo "low"
        return
    fi
    
    # Fallback to content-based analysis if no key found
    
    # Special case for login events
    if echo "$log_text_lower" | grep -E "login" > /dev/null; then
        if echo "$log_text_lower" | grep -E "failed password|authentication failure|invalid user" > /dev/null; then
            echo "high"
            return
        fi
        echo "low"
        return
    fi
    
    # Special case for syscall events
    if echo "$log_text_lower" | grep -E "syscall" > /dev/null; then
        if echo "$log_text_lower" | grep -E "execve|unlink|rmdir|delete" > /dev/null; then
            echo "medium"
            return
        fi
        echo "low"
        return
    fi
    
    # High security patterns for fallback
    local high_patterns="unauthorized|suspicious|privilege escalation|root access|failed password for root|authentication failure|user not in sudoers|permission denied|brute force|invalid user|illegal user|ssh invalid|failed login|failed auth|multiple auth failures"
    
    # Medium security patterns for fallback
    local medium_patterns="cron job|kernel module|firewall rule|pam_unix|timezone change|time zone change|chmod \+x|new user|password change|sudo command"
    
    # Check for high security patterns
    if echo "$log_text_lower" | grep -E "$high_patterns" > /dev/null; then
        echo "high"
        return
    fi
    
    # Check for medium security patterns
    if echo "$log_text_lower" | grep -E "$medium_patterns" > /dev/null; then
        echo "medium"
        return
    fi
    
    # Default to low security
    echo "low"
}

# Configuration
DB_PATH="data/site.db"  # Path to the SQLite database relative to the script
AUDIT_LOG_RETENTION_DAYS=30  # Number of days to keep audit logs
DEBUG=false  # Set to true to enable debug output

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
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

# Function to print debug messages
debug() {
    if [ "$DEBUG" = true ]; then
        echo "[DEBUG] $1" >&2
    fi
}

# Display usage information
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -u, --user USERNAME    Remote username (required)"
    echo "  -i, --ip IP_ADDRESS    Target IP address (required)"
    echo "  -k, --key KEY_PATH     Path to SSH key (required)"
    echo "  -p, --port PORT        SSH port (default: 22)"
    echo "  -d, --debug            Enable debug output"
    echo "  -h, --help             Display this help message"
    exit 1
}

# Parse command line arguments
REMOTE_USER=""
TARGET_IP=""
SSH_KEY_PATH=""
SSH_PORT="22"

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            REMOTE_USER="$2"
            shift 2
            ;;
        -i|--ip)
            TARGET_IP="$2"
            shift 2
            ;;
        -k|--key)
            SSH_KEY_PATH="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check required parameters
if [ -z "$REMOTE_USER" ] || [ -z "$TARGET_IP" ] || [ -z "$SSH_KEY_PATH" ]; then
    echo "Error: Remote username, target IP, and SSH key path are required"
    usage
fi

# Check if the SSH key exists
if [ ! -f "$SSH_KEY_PATH" ]; then
    echo " SSH key not found at $SSH_KEY_PATH"
    exit 1
fi

# Get device ID from the database - exclude deleted devices
DEVICE_ID=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;")
if [ -z "$DEVICE_ID" ]; then
    echo " Device with IP $TARGET_IP not found in the database"
    exit 1
fi

echo "Starting monitoring for device ID $DEVICE_ID ($TARGET_IP) using user $REMOTE_USER..."

# Function to retrieve audit logs from the remote device
get_audit_logs() {
    echo "Retrieving audit logs from $TARGET_IP..."
    
    # Create a temporary file to store the logs
    local temp_log_file="/tmp/audit_logs_$$.log"
    
    # Get the timestamp of the most recent log in the database for this device
    local latest_timestamp=""
    local latest_timestamp_query="SELECT MAX(event_time) FROM audit_logs WHERE device_id = '$DEVICE_ID';"
    latest_timestamp=$(execute_sqlite "$latest_timestamp_query" | grep -v "^MAX" | tr -d '[:space:]')
    
    # Clear the temp file
    > "$temp_log_file"
    
    # Build optimized SSH command with better performance options
    local ssh_opts="-i $SSH_KEY_PATH -p $SSH_PORT -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o Compression=yes -o TCPKeepAlive=yes -o ServerAliveInterval=5"
    
    # If we have a latest timestamp, only get newer logs (incremental collection)
    if [ -n "$latest_timestamp" ] && [ "$latest_timestamp" != "NULL" ]; then
        echo " Last log timestamp: $latest_timestamp - collecting incremental logs"
        
        # Fix timestamp format by adding space between date and time if missing
        local formatted_timestamp="$latest_timestamp"
        if [[ "$latest_timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
            # Insert space between date and time: 2025-06-1917:32:33 -> 2025-06-19 17:32:33
            formatted_timestamp="${latest_timestamp:0:10} ${latest_timestamp:10}"
        fi
        
        # Convert timestamp to epoch for comparison
        local epoch_time=$(date -d "$formatted_timestamp" +%s 2>/dev/null || echo "0")
        
        if [ "$epoch_time" -gt 0 ]; then
            # Get only logs newer than the latest timestamp - use entire file for accuracy
            local remote_cmd="sudo -n /usr/bin/cat /var/log/audit/audit.log 2>/dev/null | awk -v start_time=$epoch_time 'BEGIN{FS=\"audit\\\\(|\\\\)\"} {if(match(\$0, /audit\\([0-9]+\\.[0-9]+:[0-9]+\\)/) && \$2 > start_time) print \$0}'"
            timeout 15 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "$remote_cmd" > "$temp_log_file" 2>/dev/null
        else
            # Fallback: get last 1000 lines instead of entire file
            timeout 10 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "sudo -n /usr/bin/tail -n 1000 /var/log/audit/audit.log 2>/dev/null" > "$temp_log_file" 2>/dev/null
        fi
    else
        # For first run, get only recent logs (last 1000 lines) instead of entire file
        timeout 10 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "sudo -n /usr/bin/tail -n 1000 /var/log/audit/audit.log 2>/dev/null" > "$temp_log_file" 2>/dev/null
    fi
    
    # If no logs with sudo, try without sudo but with same optimizations
    if [ ! -s "$temp_log_file" ]; then
        if [ -n "$latest_timestamp" ] && [ "$latest_timestamp" != "NULL" ]; then
            # Fix timestamp format
            local formatted_timestamp="$latest_timestamp"
            if [[ "$latest_timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
                formatted_timestamp="${latest_timestamp:0:10} ${latest_timestamp:10}"
            fi
            
            local epoch_time=$(date -d "$formatted_timestamp" +%s 2>/dev/null || echo "0")
            
            if [ "$epoch_time" -gt 0 ]; then
                # Get only logs newer than the latest timestamp - use entire file for accuracy
                local remote_cmd="tail -n 10000 /var/log/audit/audit.log 2>/dev/null | awk -v start_time=$epoch_time 'BEGIN{FS=\"audit\\\\(|\\\\)\"} {if(match(\$0, /audit\\([0-9]+\\.[0-9]+:[0-9]+\\)/) && \$2 > start_time) print \$0}'"
                timeout 8 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "$remote_cmd" > "$temp_log_file" 2>/dev/null
            else
                # Simple fallback without timestamp filtering
                timeout 8 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "tail -n 1000 /var/log/audit/audit.log 2>/dev/null" > "$temp_log_file" 2>/dev/null
            fi
        else
            timeout 8 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "tail -n 1000 /var/log/audit/audit.log 2>/dev/null" > "$temp_log_file" 2>/dev/null
        fi
    fi
    
    # Final fallback: if still no logs, try basic cat command
    if [ ! -s "$temp_log_file" ]; then
        timeout 8 ssh $ssh_opts "$REMOTE_USER@$TARGET_IP" "cat /var/log/audit/audit.log 2>/dev/null | tail -n 1000" > "$temp_log_file" 2>/dev/null
    fi
    
    # Check if we got any audit logs
    if [ -s "$temp_log_file" ]; then
        local log_lines=$(wc -l < "$temp_log_file")
        echo " Successfully retrieved $log_lines lines of audit logs from $TARGET_IP"
        
        # Update device status in the database
        execute_sqlite "UPDATE devices SET status = 'online', last_updated = CURRENT_TIMESTAMP WHERE ip_address = '$TARGET_IP';"
        
        # Process the logs directly
        process_audit_logs "$temp_log_file" "$DEVICE_ID"
        
        # Clean up
        rm -f "$temp_log_file"
        return 0
    else
        echo " No audit logs retrieved from $TARGET_IP"
        
        # Update device status in the database
        execute_sqlite "UPDATE devices SET status = 'offline', last_updated = CURRENT_TIMESTAMP WHERE ip_address = '$TARGET_IP';"
        
        # Clean up
        rm -f "$temp_log_file"
        return 1
    fi
}

# Function to process and store audit logs in the database
process_audit_logs() {
    local log_file="$1"
    local device_id="$2"
    local log_count=0
    
    echo "Processing audit logs..."
    
    # Check if log file exists
    if [ ! -f "$log_file" ]; then
        echo " Log file not found"
        return 1
    fi
    
    # Check if log file is empty
    if [ ! -s "$log_file" ]; then
        echo " Log file is empty"
        return 0
    fi
    # Create a temporary SQL file for batch insert
    local temp_sql_file="/tmp/audit_batch_insert_$$.sql"
    local db_key=$(get_db_encryption_key)
    
    # Start the SQL file with pragma and begin transaction
    cat > "$temp_sql_file" << EOF
PRAGMA key = '$db_key';
BEGIN TRANSACTION;
EOF
    
    # Get existing audit IDs for this device to avoid duplicates (batch query for performance)
    local existing_audit_ids_file="/tmp/existing_audit_ids_$$.txt"
    execute_sqlite "SELECT audit_id FROM audit_logs WHERE device_id = '$device_id' AND audit_id IS NOT NULL;" > "$existing_audit_ids_file"
    
    # First pass: Group related audit log entries by their audit ID
    echo "Grouping related audit log entries..."
    
    declare -A audit_groups
    local current_audit_id=""
    local current_group=""
    local key_found=false
    
    while IFS= read -r line; do
        # Skip empty lines
        if [ -z "$line" ]; then
            continue
        fi
        
        # Skip lines that are not audit logs
        if [[ ! "$line" =~ type= ]]; then
            continue
        fi
        
        # Extract audit ID (timestamp:event_id)
        local audit_id=$(echo "$line" | grep -o 'audit([0-9]*\.[0-9]*:[0-9]*)' | sed 's/audit(\([0-9]*\.[0-9]*:[0-9]*\))/\1/')
        
        if [ -n "$audit_id" ]; then
            # Check if this is a new audit ID
            if [ "$audit_id" != "$current_audit_id" ]; then
                # Save the previous group if it exists and has a key
                if [ -n "$current_audit_id" ] && [ -n "$current_group" ]; then
                    audit_groups["$current_audit_id"]="$current_group"
                fi
                
                # Start a new group
                current_audit_id="$audit_id"
                current_group="$line"
                key_found=false
                
                # Check if this line has a key
                if [[ "$line" =~ key= ]] && [[ ! "$line" =~ key=\(null\) ]]; then
                    key_found=true
                fi
            else
                # Add to the current group
                current_group="$current_group\n$line"
                
                # Check if this line has a key
                if [[ "$line" =~ key= ]] && [[ ! "$line" =~ key=\(null\) ]]; then
                    key_found=true
                fi
            fi
        fi
    done < "$log_file"
    
    # Save the last group if it exists
    if [ -n "$current_audit_id" ] && [ -n "$current_group" ]; then
        audit_groups["$current_audit_id"]="$current_group"
    fi
    
    echo "Found ${#audit_groups[@]} audit event groups"
    
    # Second pass: Process each grouped audit log
    for audit_id in "${!audit_groups[@]}"; do
        local grouped_log="${audit_groups[$audit_id]}"
        
        # Use the first line as the base for processing
        local first_line=$(echo "$grouped_log" | head -n 1)
        
        # Skip lines that are not audit logs
        if [[ ! "$first_line" =~ type= ]]; then
            continue
        fi
        
        # Extract basic information from the log
        # Parse audit log timestamp (format: audit(1234567890.123:456))
        local audit_timestamp=$(echo "$first_line" | grep -o 'audit([0-9]*\.[0-9]*:[0-9]*)' | sed 's/audit(\([0-9]*\)\.[0-9]*:[0-9]*)/\1/')
        local event_time=""
        if [ -n "$audit_timestamp" ]; then
            # Convert Unix timestamp to readable format
            event_time=$(date -d "@$audit_timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "")
        fi
        
        # If timestamp extraction failed, use current time
        if [ -z "$event_time" ]; then
            event_time=$(date +"%Y-%m-%d %H:%M:%S")
        fi
        
        # Find the line with the key in the grouped log
        local key_line=""
        local type=""
        local key=""
        
        # Look for the SYSCALL line which typically contains the key
        key_line=$(echo "$grouped_log" | grep "type=SYSCALL" | head -n 1)
        if [ -z "$key_line" ]; then
            # If no SYSCALL line, try any line with a key
            key_line=$(echo "$grouped_log" | grep -E "key=\"?[a-zA-Z0-9_-]+\"?" | head -n 1)
        fi
        
        if [ -n "$key_line" ]; then
            type=$(echo "$key_line" | grep -o 'type=[^ ]*' | cut -d= -f2)
            # Improved key extraction to handle quotes and special characters
            key=$(echo "$key_line" | grep -o 'key="\?[a-zA-Z0-9_-]\+"\?' | sed 's/key="\?\([a-zA-Z0-9_-]\+\)"\?/\1/')
        else
            # Fallback to the first line if no key line found
            type=$(echo "$first_line" | grep -o 'type=[^ ]*' | cut -d= -f2)
            key=$(echo "$first_line" | grep -o 'key="\?[a-zA-Z0-9_-]\+"\?' | sed 's/key="\?\([a-zA-Z0-9_-]\+\)"\?/\1/')
        fi
        
        # Skip logs with ARCH suffix
        if [[ "$key" == *"ARCH"* ]]; then
            continue
        fi
        
        # Skip logs with no key or null key - more aggressive filtering
        if [ -z "$key" ] || [[ "$key" == "(null)"* ]] || [[ "$key" == "null" ]] || [[ "$key" == "" ]]; then
            continue
        fi
        
        # Check if this is a meaningful key from our audit rules
        local valid_keys="suspicious|privilege_esc|user_pass|sudoers_change|root_commands|authentication|failed_login|user_del|mac_policy|audit_tools|audit_logs|user_add|user_modification|group_add|group_modification|user_list|user_group|group_accounts|passwd_change|passwd_history|kernel_module|kernel_param|systemd_monitoring|startup_scripts|cron_events|software_mgmt|perm_mod|mount_operations|time_change|net_environment_exe|reconnaissance|command_execution|user_delete_files|unsuccessful_write|login|power_state|network_config|ssh_config|ssh_keys|package_management|service_management|auth_logs|system_logs|kernel_logs"
        
        if ! echo "$key" | grep -E "$valid_keys" > /dev/null; then
            continue
        fi
        
        # Extract message content from the grouped log
        local message=""
        local comm=""
        local exe=""
        local proctitle=""
        local syscall=""
        local acct=""
        local op=""
        
        # Look for command information
        if echo "$grouped_log" | grep -q 'comm='; then
            comm=$(echo "$grouped_log" | grep -o 'comm="[^"]*"' | head -n 1 | sed 's/comm="\(.*\)"/\1/')
        fi
        
        # Look for executable path
        if echo "$grouped_log" | grep -q 'exe='; then
            exe=$(echo "$grouped_log" | grep -o 'exe="[^"]*"' | head -n 1 | sed 's/exe="\(.*\)"/\1/')
        fi
        
        # Look for process title (command line arguments)
        if echo "$grouped_log" | grep -q 'proctitle='; then
            proctitle=$(echo "$grouped_log" | grep -o 'proctitle=[^ ]*' | head -n 1 | cut -d= -f2)
            # Convert hex-encoded proctitle to readable text if possible
            proctitle_text=$(echo "$proctitle" | xxd -r -p 2>/dev/null | tr '\0' ' ' | sed 's/^ *//;s/ *$//' || echo "")
        fi
        
        # Look for syscall information
        if echo "$grouped_log" | grep -q 'syscall='; then
            syscall=$(echo "$grouped_log" | grep -o 'syscall=[^ ]*' | head -n 1 | cut -d= -f2)
        fi
        
        # Look for account information
        if echo "$grouped_log" | grep -q 'acct='; then
            acct=$(echo "$grouped_log" | grep -o 'acct="[^"]*"' | head -n 1 | sed 's/acct="\(.*\)"/\1/')
        fi
        
        # Look for operation information
        if echo "$grouped_log" | grep -q 'op='; then
            op=$(echo "$grouped_log" | grep -o 'op=[^ ]*' | head -n 1 | cut -d= -f2)
        fi
        
        # Extract command arguments if available
        local args=""
        if echo "$grouped_log" | grep -q 'argc='; then
            local argc=$(echo "$grouped_log" | grep -o 'argc=[0-9]*' | head -n 1 | cut -d= -f2)
            if [ -n "$argc" ] && [ "$argc" -gt 0 ]; then
                for i in $(seq 0 $((argc-1))); do
                    local arg=$(echo "$grouped_log" | grep -o "a$i=\"[^\"]*\"" | head -n 1 | sed "s/a$i=\"\(.*\)\"/\1/")
                    if [ -n "$arg" ]; then
                        if [ -z "$args" ]; then
                            args="$arg"
                        else
                            args="$args $arg"
                        fi
                    fi
                done
            fi
        fi
        
        # Build a comprehensive message with priority on decoded command line
        if [ -n "$proctitle_text" ]; then
            # Prioritize decoded proctitle as it shows the actual command executed
            message="$proctitle_text"
            if [ -n "$comm" ] && [ -n "$exe" ]; then
                message="$message (process: $comm, executable: $exe)"
            elif [ -n "$comm" ]; then
                message="$message (process: $comm)"
            fi
        elif [ -n "$comm" ]; then
            if [ -n "$exe" ]; then
                message="Command: $comm ($exe)"
            else
                message="Command: $comm"
            fi
            
            # Add command arguments if available
            if [ -n "$args" ]; then
                message="$message with args: $args"
            fi
        elif [ -n "$op" ]; then
            message="Operation: $op"
        elif [ -n "$syscall" ]; then
            message="System call: $syscall"
        elif [ -n "$acct" ]; then
            message="Account: $acct"
        else
            # Use type as message if nothing else found
            message="$type event"
        fi
        
        # Apply defaults if extraction failed
        if [ -z "$type" ]; then
            type="UNKNOWN"
        fi
        
        if [ -z "$key" ]; then
            key="no_key"
        fi
        
        if [ -z "$message" ]; then
            message="Audit log entry"
        fi
        
        # Escape single quotes for SQL
        local escaped_log=$(echo "$grouped_log" | sed "s/'/''/g")
        
        # Determine security level
        local security_level=$(determine_security_level "$grouped_log")

        # Check if the audit ID already exists in the database
        local existing_audit_id=$(execute_sqlite "SELECT id FROM audit_logs WHERE device_id = '$device_id' AND audit_id = '$audit_id';")
        if [ -n "$existing_audit_id" ]; then
            echo "Skipping duplicate audit log with ID $audit_id"
            continue
        fi

        # Add INSERT statement to batch file
        # Explicitly save both timestamps:
        # - timestamp: when log arrived at server (CURRENT_TIMESTAMP)
        # - event_time: when the event actually occurred on the device
        local server_time=$(date +"%Y-%m-%d %H:%M:%S")
        echo "INSERT INTO audit_logs (device_id, timestamp, event_time, type, key, message, raw_log, security_level, audit_id) VALUES ('$device_id', '$server_time', '$event_time', '$type', '$key', '$message', '$escaped_log', '$security_level', '$audit_id');" >> "$temp_sql_file"
        
        log_count=$((log_count + 1))
    done
    
    # Complete the transaction
    echo "COMMIT;" >> "$temp_sql_file"
    
    # Execute the batch insert with a single database connection
    if [ $log_count -gt 0 ]; then
        echo " Inserting $log_count audit log entries in batch..."
        
        if sqlcipher "$DB_PATH" < "$temp_sql_file" > /dev/null 2>&1; then
            echo " Successfully inserted $log_count audit log entries into database"
        else
            echo " Failed to insert audit log entries into database"
            # Clean up and return error
            rm -f "$temp_sql_file"
            return 1
        fi
    else
        echo " No audit log entries were processed"
    fi
    
    # Clean up temporary SQL file
    rm -f "$temp_sql_file"
    
    # Clean up temporary files
    rm -f "$existing_audit_ids_file"
    if [ -f "${log_file}.tmp" ]; then
        rm -f "${log_file}.tmp"
    fi
    
    # Delete old audit logs based on retention policy (separate transaction)
    execute_sqlite "DELETE FROM audit_logs WHERE timestamp < datetime('now', '-$AUDIT_LOG_RETENTION_DAYS day');"
    echo " Removed audit logs older than $AUDIT_LOG_RETENTION_DAYS days"
    
    return 0
}

# Main execution
echo "Starting monitoring for $TARGET_IP..."

# Get and process audit logs in one step
if get_audit_logs; then
    echo "Monitoring completed successfully"
else
    echo "Monitoring failed"
    exit 1
fi
