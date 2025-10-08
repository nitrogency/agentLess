#!/bin/bash
# update-device.sh - Apply configuration changes to an enrolled device
# This script updates firewall rules, SSH settings, and other configuration
# without re-doing the full enrollment process

set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/common.sh"

# Setup cleanup trap
setup_cleanup_trap

# Display usage information
usage() {
    echo "Usage: $0 <device_id>"
    echo "  device_id    ID of the device in the database to update"
    exit 1
}

# Check if device ID is provided
if [ $# -ne 1 ]; then
    log_error "Device ID is required"
    usage
fi

DEVICE_ID="$1"

log_section "Device Configuration Update"
log_info "Device ID: $DEVICE_ID"

# Get database path
DB_PATH="$(get_config db_path)"
[[ "$DB_PATH" != /* ]] && DB_PATH="$(get_repo_root)/$DB_PATH"

if [ ! -f "$DB_PATH" ]; then
    log_error "Database not found at $DB_PATH"
    exit 1
fi

# Query device configuration from database
log_progress "Loading device configuration from database..."

DEVICE_INFO=$(execute_sqlite "SELECT ip_address, ssh_user, ssh_key_path, ssh_port, firewall_mode, firewall_allowed_ips, name, os_type, audit_arch, audit_ruleset FROM devices WHERE id = $DEVICE_ID AND status != 'deleted' LIMIT 1;" "$DB_PATH")

if [ -z "$DEVICE_INFO" ]; then
    log_error "Device with ID $DEVICE_ID not found in database"
    exit 1
fi

# Parse device info (format: ip|user|key|port|firewall_mode|firewall_ips|name|os_type|audit_arch|audit_ruleset)
IFS='|' read -r TARGET_IP SSH_USER SSH_KEY_PATH SSH_PORT FIREWALL_MODE FIREWALL_ALLOWED_IPS DEVICE_NAME OS_TYPE AUDIT_ARCH AUDIT_RULESET <<< "$DEVICE_INFO"

log_success "Device configuration loaded"
log_info "Device: $DEVICE_NAME"
log_info "IP: $TARGET_IP"
log_info "SSH User: $SSH_USER"
log_info "SSH Port: $SSH_PORT"
log_info "OS Type: $OS_TYPE"
log_info "Firewall Mode: $FIREWALL_MODE"
if [ "$OS_TYPE" = "linux" ]; then
    log_info "Audit Config: $AUDIT_RULESET (${AUDIT_ARCH})"
fi

# Validate SSH key exists
if [ ! -f "$SSH_KEY_PATH" ]; then
    log_error "SSH key not found at $SSH_KEY_PATH"
    exit 1
fi

# Test SSH connection
log_progress "Testing SSH connection to $TARGET_IP..."
if ! ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$SSH_KEY_PATH" -p "$SSH_PORT" "$SSH_USER@$TARGET_IP" "exit" 2>/dev/null; then
    log_error "Could not connect to $TARGET_IP using SSH"
    log_info "Please ensure:"
    log_info "  1. The device is online and reachable"
    log_info "  2. SSH service is running"
    log_info "  3. The monitoring user still has SSH access"
    log_info "  4. Firewall rules allow SSH from this server"
    exit 1
fi
log_success "SSH connection successful!"

# Create update script to run on target
log_progress "Preparing configuration update script..."

TMP_UPDATE_SCRIPT=$(create_temp_file "device-update")
register_temp_file "$TMP_UPDATE_SCRIPT"

cat > "$TMP_UPDATE_SCRIPT" << 'EOF'
#!/bin/bash
set -e

FIREWALL_MODE="$1"
FIREWALL_ALLOWED_IPS="$2"
SSH_PORT="$3"
OS_TYPE="$4"
UPDATE_AUDIT_RULES="$5"

echo "==================================="
echo "  Device Configuration Update"
echo "==================================="
echo ""

# Detect available firewall tool
FIREWALL_TOOL=""
if command -v ufw >/dev/null 2>&1; then
    FIREWALL_TOOL="ufw"
elif command -v iptables >/dev/null 2>&1; then
    FIREWALL_TOOL="iptables"
fi

if [ "$FIREWALL_MODE" = "disabled" ]; then
    echo "Disabling firewall..."
    
    if [ "$FIREWALL_TOOL" = "ufw" ]; then
        sudo ufw --force disable 2>/dev/null || true
        echo "UFW firewall disabled"
    elif [ "$FIREWALL_TOOL" = "iptables" ]; then
        sudo iptables -F 2>/dev/null || true
        sudo iptables -X 2>/dev/null || true
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        echo "iptables rules flushed"
    else
        echo "No firewall tool found, skipping..."
    fi
    
elif [ "$FIREWALL_MODE" != "disabled" ] && [ -n "$FIREWALL_TOOL" ]; then
    echo "Updating firewall configuration (mode: $FIREWALL_MODE)..."
    
    # Get monitoring server IP from current SSH connection
    MONITOR_SERVER_IP=$(echo $SSH_CONNECTION | awk '{print $1}')
    
    if [ -z "$MONITOR_SERVER_IP" ]; then
        echo "Warning: Could not detect monitoring server IP"
        exit 1
    fi
    
    echo "Monitoring server IP: $MONITOR_SERVER_IP"
    
    if [ "$FIREWALL_TOOL" = "ufw" ]; then
        echo "Configuring UFW firewall..."
        
        # Reset UFW to default settings
        sudo ufw --force reset >/dev/null 2>&1
        
        # Set default policies
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        
        # Configure based on mode
        if [ "$FIREWALL_MODE" = "ssh_all" ]; then
            echo "Allowing SSH from all IPs on port $SSH_PORT..."
            sudo ufw allow $SSH_PORT/tcp comment 'SSH access'
            
        elif [ "$FIREWALL_MODE" = "ssh_restricted" ]; then
            echo "Allowing SSH only from monitoring server and specified IPs..."
            
            # Always allow monitoring server
            sudo ufw allow from $MONITOR_SERVER_IP to any port $SSH_PORT proto tcp comment 'Monitoring server SSH'
            
            # Allow additional IPs if provided
            if [ -n "$FIREWALL_ALLOWED_IPS" ]; then
                IFS=',' read -ra ALLOWED_IP_ARRAY <<< "$FIREWALL_ALLOWED_IPS"
                for ip in "${ALLOWED_IP_ARRAY[@]}"; do
                    ip=$(echo $ip | xargs)  # Trim whitespace
                    if [ -n "$ip" ]; then
                        echo "Allowing SSH from $ip..."
                        sudo ufw allow from $ip to any port $SSH_PORT proto tcp comment 'Allowed admin IP'
                    fi
                done
            fi
        fi
        
        # Enable UFW
        sudo ufw --force enable
        echo "UFW firewall updated successfully"
        sudo ufw status numbered
        
    elif [ "$FIREWALL_TOOL" = "iptables" ]; then
        echo "Configuring iptables firewall..."
        
        # Flush existing rules
        sudo iptables -F
        sudo iptables -X
        
        # Set default policies
        sudo iptables -P INPUT DROP
        sudo iptables -P FORWARD DROP
        sudo iptables -P OUTPUT ACCEPT
        
        # Allow loopback
        sudo iptables -A INPUT -i lo -j ACCEPT
        
        # Allow established connections
        sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Configure based on mode
        if [ "$FIREWALL_MODE" = "ssh_all" ]; then
            echo "Allowing SSH from all IPs on port $SSH_PORT..."
            sudo iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
            
        elif [ "$FIREWALL_MODE" = "ssh_restricted" ]; then
            echo "Allowing SSH only from monitoring server and specified IPs..."
            
            # Always allow monitoring server
            sudo iptables -A INPUT -p tcp -s $MONITOR_SERVER_IP --dport $SSH_PORT -j ACCEPT
            
            # Allow additional IPs if provided
            if [ -n "$FIREWALL_ALLOWED_IPS" ]; then
                IFS=',' read -ra ALLOWED_IP_ARRAY <<< "$FIREWALL_ALLOWED_IPS"
                for ip in "${ALLOWED_IP_ARRAY[@]}"; do
                    ip=$(echo $ip | xargs)  # Trim whitespace
                    if [ -n "$ip" ]; then
                        echo "Allowing SSH from $ip..."
                        sudo iptables -A INPUT -p tcp -s $ip --dport $SSH_PORT -j ACCEPT
                    fi
                done
            fi
        fi
        
        # Save iptables rules (distribution-specific)
        if command -v iptables-save >/dev/null 2>&1; then
            if [ -d /etc/iptables ]; then
                sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null
            elif command -v netfilter-persistent >/dev/null 2>&1; then
                sudo netfilter-persistent save
            elif command -v service >/dev/null 2>&1; then
                sudo service iptables save 2>/dev/null || true
            fi
        fi
        
        echo "iptables firewall updated successfully"
        sudo iptables -L -n
    fi
else
    echo "No firewall tool found or firewall mode disabled, skipping firewall configuration..."
fi

# Update audit rules if needed (Linux only)
if [ "$OS_TYPE" = "linux" ] && [ "$UPDATE_AUDIT_RULES" = "true" ]; then
    echo ""
    echo "Updating audit rules..."
    
    if command -v auditctl >/dev/null 2>&1; then
        # Check if audit rules file was copied
        if [ -f /tmp/audit_rules_update.rules ]; then
            echo "Installing new audit ruleset..."
            
            # Backup existing rules
            if [ -f /etc/audit/rules.d/audit.rules ]; then
                sudo cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak 2>/dev/null || true
            fi
            
            # Install new rules
            sudo mkdir -p /etc/audit/rules.d
            sudo cp /tmp/audit_rules_update.rules /etc/audit/rules.d/audit.rules
            sudo rm -f /tmp/audit_rules_update.rules
            
            # Reload audit rules
            if command -v augenrules >/dev/null 2>&1; then
                echo "Reloading audit rules with augenrules..."
                sudo augenrules --load || echo "Warning: Failed to load rules with augenrules"
            else
                echo "Restarting auditd service..."
                sudo systemctl restart auditd 2>/dev/null || sudo service auditd restart 2>/dev/null || echo "Warning: Failed to restart auditd"
            fi
            
            # Verify rules loaded
            if sudo auditctl -l >/dev/null 2>&1; then
                echo "Audit rules updated successfully"
            else
                echo "Warning: Could not verify audit rules"
            fi
        else
            echo "Warning: Audit rules file not found, skipping update"
        fi
    else
        echo "Warning: auditctl not found, skipping audit rules update"
    fi
fi

echo ""
echo "Configuration update completed successfully!"
EOF

chmod +x "$TMP_UPDATE_SCRIPT"

# Copy update script to target
log_progress "Uploading update script to target device..."
scp -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -P "$SSH_PORT" "$TMP_UPDATE_SCRIPT" "$SSH_USER@$TARGET_IP:~/device_update.sh" >/dev/null 2>&1

# Copy audit rules file if Linux device
UPDATE_AUDIT_RULES="false"
if [ "$OS_TYPE" = "linux" ]; then
    # Set default values if empty
    AUDIT_ARCH="${AUDIT_ARCH:-x64}"
    AUDIT_RULESET="${AUDIT_RULESET:-audit_default.rules}"
    
    AUDIT_RULES_SOURCE="$(get_repo_root)/rulesets/${AUDIT_ARCH}/${AUDIT_RULESET}"
    
    if [ -f "$AUDIT_RULES_SOURCE" ]; then
        log_progress "Uploading audit ruleset: $AUDIT_RULESET (${AUDIT_ARCH})..."
        scp -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -P "$SSH_PORT" "$AUDIT_RULES_SOURCE" "$SSH_USER@$TARGET_IP:/tmp/audit_rules_update.rules" >/dev/null 2>&1
        UPDATE_AUDIT_RULES="true"
    else
        log_warn "Audit rules file not found at $AUDIT_RULES_SOURCE, skipping audit rules update"
    fi
fi

# Execute update script on target
log_progress "Applying configuration changes on target device..."
log_info "This may take a moment..."

if ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -t -p "$SSH_PORT" "$SSH_USER@$TARGET_IP" "bash ~/device_update.sh '$FIREWALL_MODE' '$FIREWALL_ALLOWED_IPS' '$SSH_PORT' '$OS_TYPE' '$UPDATE_AUDIT_RULES' && rm ~/device_update.sh"; then
    log_success "Configuration applied successfully!"
else
    log_error "Failed to apply configuration changes"
    log_warn "The device may be in an inconsistent state"
    exit 1
fi

# Verify connectivity after changes
log_progress "Verifying SSH connectivity after changes..."
sleep 2  # Brief pause to let firewall rules settle

if ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$SSH_KEY_PATH" -p "$SSH_PORT" "$SSH_USER@$TARGET_IP" "exit" 2>/dev/null; then
    log_success "SSH connectivity verified!"
else
    log_error "SSH connectivity test failed after configuration changes"
    log_warn "The firewall rules may have blocked the monitoring server"
    log_info "You may need to access the device directly to fix the firewall configuration"
    exit 1
fi

# Update device status in database
log_progress "Updating device status in database..."
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
execute_sqlite "UPDATE devices SET last_seen = '$TIMESTAMP', status = 'online' WHERE id = $DEVICE_ID;" "$DB_PATH"

log_success "Device configuration update completed successfully!"
log_section "Summary"
log_info "Device: $DEVICE_NAME ($TARGET_IP)"
log_info "Firewall Mode: $FIREWALL_MODE"
if [ "$FIREWALL_MODE" = "ssh_restricted" ]; then
    if [ -n "$FIREWALL_ALLOWED_IPS" ]; then
        log_info "Allowed IPs: $FIREWALL_ALLOWED_IPS (plus monitoring server)"
    else
        log_info "Allowed IPs: Monitoring server only"
    fi
elif [ "$FIREWALL_MODE" = "ssh_all" ]; then
    log_info "SSH allowed from all IPs on port $SSH_PORT"
elif [ "$FIREWALL_MODE" = "disabled" ]; then
    log_info "Firewall disabled"
fi
if [ "$OS_TYPE" = "linux" ] && [ "$UPDATE_AUDIT_RULES" = "true" ]; then
    log_info "Audit Rules: Updated to $AUDIT_RULESET (${AUDIT_ARCH})"
fi
log_info "SSH connectivity: Working"
