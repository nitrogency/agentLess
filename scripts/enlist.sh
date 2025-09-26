#!/bin/bash
# enlist.sh - Enroll a remote device for monitoring
# This script sets up SSH access and audit monitoring on a target device

set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Setup cleanup trap
setup_cleanup_trap

# Configuration with library defaults
REMOTE_USER="${REMOTE_USER:-$(get_config remote_user)}"
REMOTE_GROUP="${REMOTE_GROUP:-$(get_config remote_group)}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$(get_config ssh_key_path)}"
MONITORING_SSH_KEY_PATH="$SSH_KEY_PATH"        # Backwards compatibility
LOGIN_SSH_KEY_PATH="${LOGIN_SSH_KEY_PATH:-$HOME/.ssh/id_rsa}"  # Default login key
SSH_PORT="${SSH_PORT:-$(get_config ssh_port)}"
SERVER_PORT="$SSH_PORT"                        # Backwards compatibility - same as SSH_PORT
USE_GENERATED_NAME="${USE_GENERATED_NAME:-false}"
PASSWORD_SUDO="${PASSWORD_SUDO:-false}"
LOGIN_USER="${LOGIN_USER:-$(get_config login_user)}"

# Initialize optional variables
TARGET_IP=""
RANDOM_NAMES=false
RANDOM_KEY=false
USE_SUDO_PASSWORD="$PASSWORD_SUDO"
SUDO_PASSWORD=""

# Note: generate_random_name(), execute_sqlite(), and command_exists() 
# are now provided by the shared libraries

# Display usage information
usage() {
    echo "Usage: $0 [options] TARGET_IP"
    echo "Options:"
    echo "  -u, --user USERNAME     Remote username to create (default: ids_monitor)"
    echo "  -g, --group GROUPNAME   Remote group to create (default: ids_monitor)"
    echo "  -k, --key KEY_PATH      Path to monitoring SSH key (default: $MONITORING_SSH_KEY_PATH)"
    echo "  -l, --login USERNAME    Username to login with (default: root)"
    echo "  -K, --login-key KEY_PATH Path to login SSH key (default: $LOGIN_SSH_KEY_PATH)"
    echo "  -p, --port PORT         SSH port (default: 22)"
    echo "  -r, --random            Generate random user and group names"
    echo "  -R, --random-key        Generate random SSH key if it doesn't exist"
    echo "  -h, --help              Display this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            REMOTE_USER="$2"
            shift 2
            ;;
        -g|--group)
            REMOTE_GROUP="$2"
            shift 2
            ;;
        -k|--key)
            MONITORING_SSH_KEY_PATH="$2"
            shift 2
            ;;
        -K|--login-key)
            LOGIN_SSH_KEY_PATH="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            SERVER_PORT="$2"  # Keep both for compatibility
            shift 2
            ;;
        -r|--random)
            RANDOM_NAMES=true
            shift
            ;;
        -R|--random-key)
            RANDOM_KEY=true
            shift
            ;;
        -l|--login)
            LOGIN_USER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            TARGET_IP="$1"
            shift
            ;;
    esac
done

# Check if target IP is provided
if [ -z "$TARGET_IP" ]; then
    log_error "Target IP address is required"
    usage
fi

# Generate random names if requested
if [ "$RANDOM_NAMES" = true ]; then
    REMOTE_USER=$(generate_random_name)
    REMOTE_GROUP=$(generate_random_name)
    log_info "Generated random user: $REMOTE_USER"
    log_info "Generated random group: $REMOTE_GROUP"
fi

# Validate login SSH key
if [ ! -f "$LOGIN_SSH_KEY_PATH" ]; then
    log_error "Login SSH key not found at $LOGIN_SSH_KEY_PATH"
    log_info "Please specify a valid SSH key with -K or --login-key"
    exit 1
fi

# Check if monitoring SSH key exists, if not, generate it
if [ ! -f "$MONITORING_SSH_KEY_PATH" ]; then
    log_warn "Monitoring SSH key not found at $MONITORING_SSH_KEY_PATH"
    if [ "$RANDOM_KEY" = true ]; then
        log_progress "Generating a new SSH key pair for monitoring..."
        ssh-keygen -t rsa -b 4096 -f "$MONITORING_SSH_KEY_PATH" -N "" -C "ids_monitoring_key"
        log_success "Generated new monitoring SSH key at $MONITORING_SSH_KEY_PATH"
    else
        log_error "Please specify a valid SSH key with -k or --key"
        exit 1
    fi
fi

# Get the monitoring public key
SSH_PUB_KEY=$(cat "${MONITORING_SSH_KEY_PATH}.pub")
if [ -z "$SSH_PUB_KEY" ]; then
    handle_error "Could not read public key from ${MONITORING_SSH_KEY_PATH}.pub"
fi

# Test SSH connection to the target using the login key
log_progress "Testing SSH connection to $TARGET_IP..."
if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$LOGIN_SSH_KEY_PATH" -p "$SERVER_PORT" "$LOGIN_USER@$TARGET_IP" "exit" 2>/dev/null; then
    log_error "Could not connect to $TARGET_IP using SSH"
    log_info "Please ensure that:"
    log_info "  1. The target device is reachable"
    log_info "  2. SSH is enabled on the target"
    log_info "  3. The login user has SSH access"
    log_info "  4. You have copied your SSH key to the target using:"
    log_info "     ssh-copy-id -i ${LOGIN_SSH_KEY_PATH}.pub $LOGIN_USER@$TARGET_IP"
    exit 1
fi

log_success "SSH connection successful!"

# Set up the remote device
setup_remote_device() {
    log_progress "Setting up remote device $TARGET_IP..."
    
    # Create a temporary script file locally
    TMP_SCRIPT_FILE=$(create_temp_file "enlist-setup")
    register_temp_file "$TMP_SCRIPT_FILE"
    
    # Create the setup script with proper variable substitution
    cat > "$TMP_SCRIPT_FILE" << EOF
#!/bin/bash
set -e

# Create the group if it doesn't exist
if ! getent group $REMOTE_GROUP > /dev/null; then
    if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
        echo "\$SUDO_PASSWORD" | sudo -S groupadd $REMOTE_GROUP
    else
        sudo groupadd $REMOTE_GROUP
    fi
fi

# Create the user if it doesn't exist
if ! id $REMOTE_USER &>/dev/null; then
    if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
        echo "\$SUDO_PASSWORD" | sudo -S useradd -m -g $REMOTE_GROUP -s /bin/bash $REMOTE_USER
    else
        sudo useradd -m -g $REMOTE_GROUP -s /bin/bash $REMOTE_USER
    fi
fi

# Add the monitoring user to the adm group for audit log access
if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
    echo "\$SUDO_PASSWORD" | sudo -S usermod -a -G adm $REMOTE_USER
else
    sudo usermod -a -G adm $REMOTE_USER
fi

# Set up the .ssh directory
sudo mkdir -p /home/$REMOTE_USER/.ssh
echo "\$SSH_PUB_KEY" | sudo tee /home/$REMOTE_USER/.ssh/authorized_keys > /dev/null
sudo chmod 700 /home/$REMOTE_USER/.ssh
sudo chmod 600 /home/$REMOTE_USER/.ssh/authorized_keys
sudo chown -R $REMOTE_USER:$REMOTE_GROUP /home/$REMOTE_USER/.ssh

# Enable SSH key authentication
sudo grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config || {
    echo "Enabling SSH key authentication..."
    sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    if ! sudo grep -q "PubkeyAuthentication" /etc/ssh/sshd_config; then
        sudo bash -c 'echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config'
    fi
    if sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null; then
        echo "SSH service restarted"
    else
        echo "SSH changes will apply on next connection"
    fi
}

# Configure audit log access
echo "Configuring audit access for $REMOTE_USER..."
sudo bash -c "echo \"$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail /var/log/audit/audit.log, /usr/bin/cat /var/log/audit/audit.log\" > /etc/sudoers.d/$REMOTE_USER"
sudo chmod 440 /etc/sudoers.d/$REMOTE_USER

# Install and configure auditd
echo "Setting up audit daemon..."
AUDITD_INSTALLED=false

if command -v auditctl >/dev/null 2>&1; then
    echo "auditctl found, checking service..."
    if sudo systemctl is-active auditd >/dev/null 2>&1; then
        echo "auditd is active"
        AUDITD_INSTALLED=true
    elif sudo systemctl is-enabled auditd >/dev/null 2>&1; then
        echo "Starting auditd service..."
        sudo systemctl start auditd || echo "Warning: Failed to start auditd"
        AUDITD_INSTALLED=true
    else
        echo "Enabling auditd service..."
        sudo systemctl enable auditd || echo "Warning: Failed to enable auditd"
        sudo systemctl start auditd || echo "Warning: Failed to start auditd"
        AUDITD_INSTALLED=true
    fi
else
    echo "Installing auditd..."
    sudo apt-get update -q || echo "Warning: Package update failed"
    if sudo apt-get install -y auditd audispd-plugins; then
        echo "auditd installed"
        sudo systemctl enable auditd || echo "Warning: Failed to enable auditd"
        sudo systemctl start auditd || echo "Warning: Failed to start auditd"
        if command -v auditctl >/dev/null 2>&1; then
            echo "auditctl available"
            AUDITD_INSTALLED=true
        else
            echo "auditctl still unavailable"
            AUDITD_INSTALLED=false
        fi
    else
        echo "Failed to install auditd"
        AUDITD_INSTALLED=false
    fi
fi

# Configure audit rules
if command -v auditctl >/dev/null 2>&1; then
    AUDITD_INSTALLED=true
    echo "Configuring audit rules..."
    
    if ! sudo systemctl status auditd >/dev/null 2>&1; then
        sudo systemctl enable auditd || echo "Warning: Failed to enable auditd"
        sudo systemctl start auditd || echo "Warning: Failed to start auditd"
    fi
    
    sudo rm -f /etc/audit/rules.d/audit.rules 2>/dev/null || echo "Warning: Could not remove existing rules"
    
    if [ ! -d "/etc/audit/rules.d" ]; then
        sudo mkdir -p /etc/audit/rules.d || {
            echo "Warning: Could not create rules directory"
            AUDITD_INSTALLED=false
            return 0
        }
    fi
    
    UID_MIN=\$(awk '/^\s*UID_MIN/{print \$2}' /etc/login.defs 2>/dev/null || true)
    [ -z "\$UID_MIN" ] && UID_MIN=1000
    MONITOR_UID=\$(id -u $REMOTE_USER 2>/dev/null || echo 0)

    if [ ! -f "/tmp/audit_default.rules" ]; then
        echo "Error: audit rules file not found in /tmp/"
        exit 1
    fi
    
    if ! sudo cp /tmp/audit_default.rules /etc/audit/rules.d/audit.rules; then
        echo "Error: Failed to copy audit rules"
        exit 1
    fi
    
    rm -f /tmp/audit_default.rules
    echo "Audit rules installed"

    if command -v augenrules >/dev/null 2>&1; then
        sudo augenrules --load || echo "Warning: Failed to load rules"
    else
        sudo systemctl restart auditd || echo "Warning: Failed to restart auditd"
    fi

    sudo auditctl -l >/dev/null || echo "Warning: Could not verify rules"
else
    echo "Skipping audit rules setup - auditctl unavailable"
    AUDITD_INSTALLED=false
fi

echo "Audit rules configured for persistence"

# Enable audit logging
if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
    echo "\$SUDO_PASSWORD" | sudo -S auditctl -e 1 || echo "Warning: Could not enable audit logging"
else
    sudo auditctl -e 1 || echo "Warning: Could not enable audit logging"
fi

echo "Setup completed"
EOF
    
    # Make the script executable
    chmod +x "$TMP_SCRIPT_FILE"
    
    # Copy the script to the target
    scp -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -P "$SERVER_PORT" "$TMP_SCRIPT_FILE" "$LOGIN_USER@$TARGET_IP:~/setup_ids_monitor.sh"
    
    # Create a temporary file with the SSH public key
    SSH_KEY_TMP_FILE=$(create_temp_file "ssh-key")
    register_temp_file "$SSH_KEY_TMP_FILE"
    echo "$SSH_PUB_KEY" > "$SSH_KEY_TMP_FILE"
    
    # Copy the SSH key to the target
    scp -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -P "$SERVER_PORT" "$SSH_KEY_TMP_FILE" "$LOGIN_USER@$TARGET_IP:~/ids_monitor.pub"
    
    # Determine the audit rules file path using shared functions
    AUDIT_RULES_SOURCE="$(get_repo_root)/$(get_config audit_rules_source_path)"
    
    # Check if the audit rules file exists and copy it
    if [ -f "$AUDIT_RULES_SOURCE" ]; then
        echo "Copying audit rules file to target..."
        scp -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -P "$SERVER_PORT" "$AUDIT_RULES_SOURCE" "$LOGIN_USER@$TARGET_IP:/tmp/audit_default.rules"
    else
        handle_error "audit_default.rules file not found at $AUDIT_RULES_SOURCE" 1 "Please ensure the rulesets/audit_default.rules file exists in the project directory"
    fi
    
    # Run the script on the target with a pseudo-terminal allocation
    ssh -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -t -p "$SERVER_PORT" "$LOGIN_USER@$TARGET_IP" "export USE_SUDO_PASSWORD=\"$USE_SUDO_PASSWORD\"; export SUDO_PASSWORD=\"$SUDO_PASSWORD\"; export SSH_PUB_KEY=\"\$(cat ~/ids_monitor.pub)\"; bash ~/setup_ids_monitor.sh && rm ~/setup_ids_monitor.sh ~/ids_monitor.pub"
    
    # Temp files will be cleaned up automatically by trap
    
    # Test connection with the new user
    log_progress "Testing connection with the monitoring user..."
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$MONITORING_SSH_KEY_PATH" -p "$SERVER_PORT" -v "$REMOTE_USER@$TARGET_IP" "echo 'SSH connection successful!'; exit" 2>&1 | tee /tmp/ssh_debug.log; then
        log_success "Monitoring user setup successful!"
    else
        log_error "Failed to connect with the monitoring user."
        log_info "This could be due to:"
        log_info "  1. SSH key authentication issues"
        log_info "  2. Incorrect permissions on the authorized_keys file"
        log_info "  3. SSH configuration on the target device"
        log_info ""
        log_info "Debug information from SSH connection attempt:"
        cat /tmp/ssh_debug.log
        log_info ""
        log_error "Please check the SSH configuration manually."
        exit 1
    fi
    
    # Re-enable audit logging is handled in the script
}

# Register the device with the IDS server
# Update device in database with actual generated username and group
update_device_in_database() {
    log_progress "Updating device in database with actual generated username and group..."
    
    # Get the correct database path
    local DB_PATH="$(get_repo_root)/$(get_config db_path)"
    
    # Find the device ID by IP address
    DEVICE_ID=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH")
    
    if [ -z "$DEVICE_ID" ]; then
        log_warn "Device with IP $TARGET_IP not found in the database"
        return 1
    fi
    
    # Update the device with the actual generated username and group
    execute_sqlite "UPDATE devices SET ssh_user = '$REMOTE_USER', ssh_group = '$REMOTE_GROUP', hostname = '$HOSTNAME', os_info = '$OS_INFO' WHERE id = $DEVICE_ID;" "$DB_PATH"
    
    log_success "Device updated in database with actual username: $REMOTE_USER"
    return 0
}

# Clear any audit logs in the database for this device
clear_device_audit_logs() {
    log_progress "Clearing any existing audit logs for the device from the database..."
    
    # Get the correct database path
    local DB_PATH="$(get_repo_root)/$(get_config db_path)"
    
    # Find the device ID by IP address
    DEVICE_ID=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH")
    
    if [ -z "$DEVICE_ID" ]; then
        log_warn "Device with IP $TARGET_IP not found in the database"
        return 1
    fi
    
    # Count how many logs will be deleted
    LOG_COUNT=$(execute_sqlite "SELECT COUNT(*) FROM audit_logs WHERE device_id = $DEVICE_ID;" "$DB_PATH")
    
    # Delete all audit logs for this device
    execute_sqlite "DELETE FROM audit_logs WHERE device_id = $DEVICE_ID;" "$DB_PATH"
    
    log_success "Cleared $LOG_COUNT audit logs for device ID: $DEVICE_ID"
    return 0
}

register_with_server() {
    log_progress "Registering device with IDS server..."
    
    # Prepare SSH command for the monitoring user
    MONITOR_SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=\"$(get_config ssh_connect_timeout)\" -i \"$MONITORING_SSH_KEY_PATH\" -p \"$SERVER_PORT\" $REMOTE_USER@\"$TARGET_IP\""
    
    # Get device information
    HOSTNAME=$(eval "$MONITOR_SSH_CMD \"hostname\"")
    OS_INFO=$(eval "$MONITOR_SSH_CMD \"cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\\\"'\"")
    
    # Here you would typically make an API call to your server to register the device
    # For demonstration purposes, we'll just echo the information
    log_info "Device information:"
    log_info "  IP: $TARGET_IP"
    log_info "  Hostname: $HOSTNAME"
    log_info "  OS: $OS_INFO"
    log_info "  User: $REMOTE_USER"
    log_info "  Group: $REMOTE_GROUP"
    
    # Update the device in the database with the actual generated username and group
    update_device_in_database
    
    log_success "Device registered successfully!"
}

# Main execution
log_section "Device Enrollment"
log_info "Target IP: $TARGET_IP"
log_info "Remote User: $REMOTE_USER"
log_info "Remote Group: $REMOTE_GROUP"
log_info "SSH Key: $MONITORING_SSH_KEY_PATH"

setup_remote_device
register_with_server

# Clear any audit logs generated during setup
clear_device_audit_logs

log_success "Device enrollment completed successfully!"
log_info "You can now monitor this device through your IDS dashboard."
log_section "Important Credentials"
log_info "SSH User: $REMOTE_USER"
log_info "SSH Group: $REMOTE_GROUP"
log_info "SSH Key: $MONITORING_SSH_KEY_PATH"

# Set up monitoring services for all enrolled devices
log_section "Monitoring Services Setup"
log_progress "Setting up monitoring services..."
SETUP_MONITORING_SCRIPT="$SCRIPT_DIR/setup-monitoring.sh"

if [ -f "$SETUP_MONITORING_SCRIPT" ]; then
    log_info "Launching setup-monitoring.sh to configure systemd services..."
    bash "$SETUP_MONITORING_SCRIPT"
    log_success "Monitoring setup completed!"
else
    log_warn "setup-monitoring.sh not found at $SETUP_MONITORING_SCRIPT"
    log_info "You may need to run it manually to start monitoring services."
fi