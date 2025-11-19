#!/bin/bash
# enlist.sh - Enroll a remote device for monitoring
# This script sets up SSH access and audit monitoring on a target device

set -eo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Load database encryption key
if [ -f "/etc/agentless/secrets.env" ]; then
    # shellcheck disable=SC1091
    source /etc/agentless/secrets.env
fi

DEVICE_ID="${DEVICE_ID:-unknown}"

# Setup cleanup trap
setup_cleanup_trap

# Setup interrupt handling
setup_interrupt_trap "enlist.sh"

# Configuration with library defaults
REMOTE_USER="${REMOTE_USER:-$(get_config remote_user)}"
REMOTE_GROUP="${REMOTE_GROUP:-$(get_config remote_group)}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$(get_config ssh_key_path)}"
SSH_PORT="${SSH_PORT:-$(get_config ssh_port)}"
USE_GENERATED_NAME="${USE_GENERATED_NAME:-false}"
PASSWORD_SUDO="${PASSWORD_SUDO:-false}"
LOGIN_USER="${LOGIN_USER:-$(get_config login_user)}"

# Initialize optional variables
TARGET_IP=""
USE_SUDO_PASSWORD="$PASSWORD_SUDO"
SUDO_PASSWORD=""

# Note: execute_sqlite() and command_exists() are provided by the shared libraries

log_section "Linux device enrollment"

# Display usage information
usage() {
    echo "Usage: $0 [options] TARGET_IP"
    echo "Options:"
    echo "  -u, --user USERNAME     Remote username to create (default: ids_monitor)"
    echo "  -g, --group GROUPNAME   Remote group to create (default: ids_monitor)"
    echo "  -k, --key KEY_PATH      Path to SSH key for login and monitoring (default: $SSH_KEY_PATH)"
    echo "  -l, --login USERNAME    Username to login with (default: root)"
    echo "  -p, --port PORT         SSH port (default: 22)"
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
            SSH_KEY_PATH="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
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

# Validate SSH key
if [ ! -f "$SSH_KEY_PATH" ]; then
    log_error "SSH key not found at $SSH_KEY_PATH"
    log_info "Please specify a valid SSH key with -k or --key"
    exit 1
fi

# Try to load audit settings from database if not provided via configuration
DB_PATH="$(get_config db_path)"
# Prepend repo root if path is relative
[[ "$DB_PATH" != /* ]] && DB_PATH="$(get_repo_root)/$DB_PATH"
if [ -f "$DB_PATH" ]; then
    DB_AUDIT_ARCH=$(execute_sqlite "SELECT audit_arch FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH" 2>/dev/null || echo "")
    DB_AUDIT_RULESET=$(execute_sqlite "SELECT audit_ruleset FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH" 2>/dev/null || echo "")

    if [ -n "$DB_AUDIT_ARCH" ]; then
        AUDIT_ARCH="$DB_AUDIT_ARCH"
        log_info "Loaded audit architecture from database: $AUDIT_ARCH"
    fi

    if [ -n "$DB_AUDIT_RULESET" ]; then
        AUDIT_RULESET="$DB_AUDIT_RULESET"
        log_info "Loaded audit ruleset from database: $AUDIT_RULESET"
    fi
fi

# Set default audit configuration if not specified
AUDIT_ARCH="${AUDIT_ARCH:-x64}"
AUDIT_RULESET="${AUDIT_RULESET:-audit_default.rules}"

# Check if SSH key exists, if not, generate it
if [ ! -f "$SSH_KEY_PATH" ]; then
    log_warn "SSH key not found at $SSH_KEY_PATH"
    if [ "$RANDOM_KEY" = true ]; then
        log_progress "Generating a new SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N "" -C "monitor"
        log_success "Generated new SSH key at $SSH_KEY_PATH"
    else
        log_error "Please specify a valid SSH key with -k or --key"
        exit 1
    fi
fi

# Get the public key
SSH_PUB_KEY=$(cat "${SSH_KEY_PATH}.pub")
if [ -z "$SSH_PUB_KEY" ]; then
    handle_error "Could not read public key from ${SSH_KEY_PATH}.pub"
fi

# Test SSH connection to the target
log_progress "Testing SSH connection to $TARGET_IP..."
if ! ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$SSH_KEY_PATH" -p "$SSH_PORT" "$LOGIN_USER@$TARGET_IP" "exit" 2>/dev/null; then
    log_error "Could not connect to $TARGET_IP using SSH"
    log_info "Please ensure that:"
    log_info "  1. The target device is reachable"
    log_info "  2. SSH is enabled on the target"
    log_info "  3. The login user has SSH access"
    log_info "  4. You have copied your SSH key to the target using:"
    log_info "     ssh-copy-id -i ${SSH_KEY_PATH}.pub $LOGIN_USER@$TARGET_IP"
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

# Add the monitoring user to appropriate groups for audit log access
echo "Configuring log file access groups..."
if getent group adm >/dev/null 2>&1; then
    echo "Adding $REMOTE_USER to adm group..."
    if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
        echo "\$SUDO_PASSWORD" | sudo -S usermod -a -G adm $REMOTE_USER
    else
        sudo usermod -a -G adm $REMOTE_USER
    fi
elif getent group systemd-journal >/dev/null 2>&1; then
    echo "adm group not found, adding $REMOTE_USER to systemd-journal group..."
    if [ "\$USE_SUDO_PASSWORD" = "true" ]; then
        echo "\$SUDO_PASSWORD" | sudo -S usermod -a -G systemd-journal $REMOTE_USER
    else
        sudo usermod -a -G systemd-journal $REMOTE_USER
    fi
else
    echo "Warning: Neither adm nor systemd-journal group found. Will rely on sudoers configuration."
fi

# Set up the .ssh directory
sudo mkdir -p /home/$REMOTE_USER/.ssh

# Add SSH key to authorized_keys
AUTHORIZED_KEYS="/home/$REMOTE_USER/.ssh/authorized_keys"
sudo touch "\$AUTHORIZED_KEYS"

# Check if this specific key is already present
if ! sudo grep -qF "\$SSH_PUB_KEY" "\$AUTHORIZED_KEYS" 2>/dev/null; then
    echo "\$SSH_PUB_KEY" | sudo tee -a "\$AUTHORIZED_KEYS" > /dev/null
    echo "SSH key added to authorized_keys"
else
    echo "SSH key already present in authorized_keys"
fi

sudo chmod 700 /home/$REMOTE_USER/.ssh
sudo chmod 600 "\$AUTHORIZED_KEYS"
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

# Configure audit+clamav log access via sudoers
echo "Configuring passwordless sudo for log file access..."
SUDOERS_FILE="/etc/sudoers.d/$REMOTE_USER"
sudo bash -c "cat > \$SUDOERS_FILE" <<EOSUDOERS
# Allow $REMOTE_USER to read audit and ClamAV logs without password
# This is required for AgentLess IDS monitoring
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail /var/log/audit/audit.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -n * /var/log/audit/audit.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -F /var/log/audit/audit.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -n * -F /var/log/audit/audit.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/cat /var/log/audit/audit.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail /var/log/clamav/clamav.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -n * /var/log/clamav/clamav.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -F /var/log/clamav/clamav.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/tail -n * -F /var/log/clamav/clamav.log
$REMOTE_USER ALL=(root) NOPASSWD: /usr/bin/cat /var/log/clamav/clamav.log
EOSUDOERS

sudo chmod 440 "\$SUDOERS_FILE"

# Validate sudoers file
if sudo visudo -c -f "\$SUDOERS_FILE" >/dev/null 2>&1; then
    echo "Sudoers configuration validated successfully"
else
    echo "Error: Invalid sudoers configuration, removing file..."
    sudo rm -f "\$SUDOERS_FILE"
    echo "Warning: Passwordless sudo configuration failed. Manual configuration may be required."
fi

# Install and configure ClamAV
echo "Setting up ClamAV antivirus..."
CLAMAV_INSTALLED=false

if command -v clamscan >/dev/null 2>&1; then
    echo "ClamAV already installed"
    CLAMAV_INSTALLED=true
else
    echo "Installing ClamAV..."
    
    # Detect OS on remote system
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        REMOTE_OS_ID=\$ID
    else
        echo "Warning: Cannot detect remote OS, assuming Debian-based"
        REMOTE_OS_ID="debian"
    fi
    
    # Install ClamAV based on detected OS
    case \$REMOTE_OS_ID in
        ubuntu|debian)
            echo "Installing ClamAV on Debian/Ubuntu system..."
            sudo apt-get update -q || echo "Warning: Package update failed"
            if sudo apt-get install -y clamav clamav-daemon clamav-freshclam; then
                echo "ClamAV installed"
                CLAMAV_INSTALLED=true
            else
                echo "Failed to install ClamAV"
                CLAMAV_INSTALLED=false
            fi
            ;;
        fedora|rhel|centos|rocky|almalinux)
            echo "Installing ClamAV on RHEL system..."
            # Try dnf first, fall back to yum
            if command -v dnf >/dev/null 2>&1; then
                # Enable EPEL repository for ClamAV
                if ! sudo dnf repolist | grep -q epel; then
                    echo "Enabling EPEL repository..."
                    sudo dnf install -y epel-release || echo "Warning: Failed to install EPEL"
                fi
                if sudo dnf install -y clamav clamav-update clamd; then
                    echo "ClamAV installed via dnf"
                    CLAMAV_INSTALLED=true
                else
                    echo "Failed to install ClamAV via dnf"
                    CLAMAV_INSTALLED=false
                fi
            elif command -v yum >/dev/null 2>&1; then
                # Enable EPEL repository for ClamAV
                if ! sudo yum repolist | grep -q epel; then
                    echo "Enabling EPEL repository..."
                    sudo yum install -y epel-release || echo "Warning: Failed to install EPEL"
                fi
                if sudo yum install -y clamav clamav-update clamd; then
                    echo "ClamAV installed via yum"
                    CLAMAV_INSTALLED=true
                else
                    echo "Failed to install ClamAV via yum"
                    CLAMAV_INSTALLED=false
                fi
            else
                echo "No package manager found (dnf/yum)"
                CLAMAV_INSTALLED=false
            fi
            ;;
        sles|opensuse*)
            echo "Installing ClamAV on SUSE system..."
            if sudo zypper install -y clamav; then
                echo "ClamAV installed via zypper"
                CLAMAV_INSTALLED=true
            else
                echo "Failed to install ClamAV via zypper"
                CLAMAV_INSTALLED=false
            fi
            ;;
        *)
            echo "Unsupported OS for automatic ClamAV installation: \$REMOTE_OS_ID"
            echo "Please install ClamAV manually on the target system"
            CLAMAV_INSTALLED=false
            ;;
    esac
    
    # Configure and start ClamAV services if installation succeeded
    if [ "\$CLAMAV_INSTALLED" = "true" ]; then
        echo "Configuring ClamAV..."
        
        # Create log directory if it doesn't exist
        sudo mkdir -p /var/log/clamav
        
        # Configure freshclam (disable Example line)
        if [ -f /etc/clamav/freshclam.conf ]; then
            # Debian/Ubuntu path
            sudo sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true
        elif [ -f /etc/freshclam.conf ]; then
            # RHEL/CentOS path
            sudo sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
        fi
        
        # Configure clamd (disable Example line)
        if [ -f /etc/clamav/clamd.conf ]; then
            # Debian/Ubuntu path
            sudo sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true
        elif [ -f /etc/clamd.conf ]; then
            # RHEL/CentOS path
            sudo sed -i 's/^Example/#Example/' /etc/clamd.conf 2>/dev/null || true
        elif [ -f /etc/clamd.d/scan.conf ]; then
            # Alternative RHEL path
            sudo sed -i 's/^Example/#Example/' /etc/clamd.d/scan.conf 2>/dev/null || true
        fi
        
        # Stop freshclam service before manual update (avoid log file lock conflict)
        if sudo systemctl is-active clamav-freshclam >/dev/null 2>&1; then
            echo "Stopping freshclam service temporarily for initial database update..."
            sudo systemctl stop clamav-freshclam
        fi
        
        # Update virus definitions (this MUST complete before starting daemon)
        echo "Updating ClamAV virus definitions (this may take a few minutes)..."
        if sudo freshclam; then
            echo "Virus definitions updated successfully"
        else
            echo "Warning: freshclam update failed, trying to continue anyway"
        fi
        
        # Wait a moment for files to settle
        sleep 2
        
        # Enable and start freshclam service for automatic updates
        if sudo systemctl list-unit-files | grep -q clamav-freshclam; then
            sudo systemctl enable clamav-freshclam 2>/dev/null || true
            sudo systemctl start clamav-freshclam 2>/dev/null || true
            echo "Freshclam service enabled for automatic updates"
        fi
        
        # Enable and start ClamAV daemon if available
        echo "Starting ClamAV daemon..."
        if sudo systemctl list-unit-files | grep -q clamav-daemon; then
            sudo systemctl enable clamav-daemon 2>/dev/null || true
            sudo systemctl start clamav-daemon 2>/dev/null || echo "Warning: clamav-daemon may need manual start after database update completes"
        elif sudo systemctl list-unit-files | grep -q clamd; then
            sudo systemctl enable clamd 2>/dev/null || true
            sudo systemctl start clamd 2>/dev/null || echo "Warning: clamd may need manual start after database update completes"
        fi
        
        # Set up log file permissions
        if [ -f /var/log/clamav/clamav.log ]; then
            sudo chmod 644 /var/log/clamav/clamav.log
        else
            sudo touch /var/log/clamav/clamav.log
            sudo chmod 644 /var/log/clamav/clamav.log
        fi
        
        # Add monitoring user to clamav group if it exists
        if getent group clamav >/dev/null 2>&1; then
            sudo usermod -a -G clamav $REMOTE_USER || echo "Warning: Could not add user to clamav group"
        fi
        
        # Install cron if not present
        echo "Ensuring cron is installed..."
        if ! command -v crontab >/dev/null 2>&1; then
            case \$REMOTE_OS_ID in
                ubuntu|debian)
                    sudo apt-get install -y cron || echo "Warning: Failed to install cron"
                    ;;
                fedora|rhel|centos|rocky|almalinux)
                    if command -v dnf >/dev/null 2>&1; then
                        sudo dnf install -y cronie || echo "Warning: Failed to install cronie"
                    elif command -v yum >/dev/null 2>&1; then
                        sudo yum install -y cronie || echo "Warning: Failed to install cronie"
                    fi
                    ;;
                sles|opensuse*)
                    sudo zypper install -y cron || echo "Warning: Failed to install cron"
                    ;;
            esac
            
            # Enable and start cron service
            if sudo systemctl list-unit-files | grep -q '^cron.service'; then
                sudo systemctl enable cron || echo "Warning: Failed to enable cron"
                sudo systemctl start cron || echo "Warning: Failed to start cron"
            elif sudo systemctl list-unit-files | grep -q '^crond.service'; then
                sudo systemctl enable crond || echo "Warning: Failed to enable crond"
                sudo systemctl start crond || echo "Warning: Failed to start crond"
            fi
        fi
        
        # Create daily ClamAV scan script from template
        echo "Configuring daily ClamAV scans..."
        sudo mkdir -p /etc/cron.daily
        
        # Get device ID from environment variable (if set by web UI)
        DEVICE_ID="${DEVICE_ID:-unknown}"
        
        # Set defaults
        CLAMAV_SCAN_DIRS="$(get_config clamav_scan_dirs)"
        CLAMAV_QUARANTINE="$(get_config clamav_quarantine)"
        
        # Try to load device-specific config if available
        DEVICE_CONFIG="/etc/agentless/devices/${DEVICE_ID}.conf"
        if [ "$DEVICE_ID" != "unknown" ] && [ -f "$DEVICE_CONFIG" ]; then
            echo "Loading device-specific ClamAV configuration from $DEVICE_CONFIG"
            source "$DEVICE_CONFIG"
            # Config may override CLAMAV_SCAN_DIRS and CLAMAV_QUARANTINE
        fi
        
        # Use template if available, otherwise fallback to defaults
        PROJECT_ROOT="$(get_repo_root)"
        TEMPLATE_FILE="$PROJECT_ROOT/scripts/cron/clamav-scan.template"
        
        if [ -f "$TEMPLATE_FILE" ]; then
            echo "Using ClamAV cron template"
            sed -e "s|__DEVICE_ID__|${DEVICE_ID}|g" \
                -e "s|__SCAN_DIRS__|${CLAMAV_SCAN_DIRS}|g" \
                -e "s|__QUARANTINE_DIR__|${CLAMAV_QUARANTINE}|g" \
                "$TEMPLATE_FILE" | sudo tee /etc/cron.daily/clamav-scan > /dev/null
        else
            echo "Warning: Template not found at $TEMPLATE_FILE, using default configuration"
            # Fallback to hardcoded script
            sudo tee /etc/cron.daily/clamav-scan > /dev/null << 'CRON_EOF'
#!/bin/bash
# Daily ClamAV scan - logs malware detections for monitoring

SCAN_DIRS="/home /opt /var/www /tmp /var/tmp /usr/local"
LOG_FILE="/var/log/clamav/clamav.log"

# Ensure log directory exists
mkdir -p /var/log/clamav

# Run scan and append to log
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting daily scan" >> "\$LOG_FILE"

for dir in \$SCAN_DIRS; do
    if [ -d "\$dir" ]; then
        clamscan -r -i "\$dir" 2>&1 | grep -E "FOUND|-------" >> "\$LOG_FILE" 2>/dev/null || true
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S') - Daily scan completed" >> "\$LOG_FILE"
CRON_EOF
        fi
        
        sudo chmod 755 /etc/cron.daily/clamav-scan
        echo "Daily ClamAV scan configured in /etc/cron.daily/clamav-scan"
        
        if [ "$DEVICE_ID" != "unknown" ] && [ -f "$DEVICE_CONFIG" ]; then
            echo "Using device-specific scan directories: $CLAMAV_SCAN_DIRS"
        else
            echo "Using default scan directories"
        fi
        
        echo "Scans will run daily and log to /var/log/clamav/clamav.log"
        
        echo "ClamAV setup completed"
    fi
fi

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
    
    # Detect OS on remote system
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        REMOTE_OS_ID=\$ID
    else
        echo "Warning: Cannot detect remote OS, assuming Debian-based"
        REMOTE_OS_ID="debian"
    fi
    
    # Install auditd based on detected OS
    case \$REMOTE_OS_ID in
        ubuntu|debian)
            echo "Installing auditd on Debian/Ubuntu system..."
            sudo apt-get update -q || echo "Warning: Package update failed"
            if sudo apt-get install -y auditd audispd-plugins; then
                echo "auditd installed"
                AUDITD_INSTALLED=true
            else
                echo "Failed to install auditd"
                AUDITD_INSTALLED=false
            fi
            ;;
        fedora|rhel|centos|rocky|almalinux)
            echo "Installing auditd on RHEL system..."
            # Try dnf first (newer systems), fall back to yum
            if command -v dnf >/dev/null 2>&1; then
                if sudo dnf install -y audit; then
                    echo "auditd installed via dnf"
                    AUDITD_INSTALLED=true
                else
                    echo "Failed to install auditd via dnf"
                    AUDITD_INSTALLED=false
                fi
            elif command -v yum >/dev/null 2>&1; then
                if sudo yum install -y audit; then
                    echo "auditd installed via yum"
                    AUDITD_INSTALLED=true
                else
                    echo "Failed to install auditd via yum"
                    AUDITD_INSTALLED=false
                fi
            else
                echo "No package manager found (dnf/yum)"
                AUDITD_INSTALLED=false
            fi
            ;;
        sles|opensuse*)
            echo "Installing auditd on SUSE system..."
            if sudo zypper install -y audit; then
                echo "auditd installed via zypper"
                AUDITD_INSTALLED=true
            else
                echo "Failed to install auditd via zypper"
                AUDITD_INSTALLED=false
            fi
            ;;
        *)
            echo "Unsupported OS for automatic auditd installation: \$REMOTE_OS_ID"
            echo "Please install auditd manually on the target system"
            AUDITD_INSTALLED=false
            ;;
    esac
    
    # Enable and start auditd service if installation succeeded
    if [ "\$AUDITD_INSTALLED" = "true" ]; then
        sudo systemctl enable auditd || echo "Warning: Failed to enable auditd"
        sudo systemctl start auditd || echo "Warning: Failed to start auditd"
        if command -v auditctl >/dev/null 2>&1; then
            echo "auditctl available"
            AUDITD_INSTALLED=true
        else
            echo "auditctl still unavailable"
            AUDITD_INSTALLED=false
        fi
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
    scp -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -P "$SSH_PORT" "$TMP_SCRIPT_FILE" "$LOGIN_USER@$TARGET_IP:~/setup_ids_monitor.sh"
    
    # Create a temporary file with the SSH public key
    SSH_KEY_TMP_FILE=$(create_temp_file "ssh-key")
    register_temp_file "$SSH_KEY_TMP_FILE"
    echo "$SSH_PUB_KEY" > "$SSH_KEY_TMP_FILE"
    
    # Copy the SSH key to the target
    scp -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -P "$SSH_PORT" "$SSH_KEY_TMP_FILE" "$LOGIN_USER@$TARGET_IP:~/ids_monitor.pub"
    
    # Determine the audit rules file path based on architecture and ruleset
    AUDIT_RULES_SOURCE="$(get_repo_root)/rulesets/${AUDIT_ARCH}/${AUDIT_RULESET}"
    
    # Check if the audit rules file exists and copy it
    if [ -f "$AUDIT_RULES_SOURCE" ]; then
        log_info "Using audit ruleset: $AUDIT_RULESET (${AUDIT_ARCH})"
        echo "Copying audit rules file to target..."
        scp -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -P "$SSH_PORT" "$AUDIT_RULES_SOURCE" "$LOGIN_USER@$TARGET_IP:/tmp/audit_default.rules"
    else
        handle_error "Audit rules file not found at $AUDIT_RULES_SOURCE" 1 "Please ensure the file exists in the rulesets/${AUDIT_ARCH}/ directory"
    fi
    
    # Run the script on the target with a pseudo-terminal allocation
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i "$SSH_KEY_PATH" -t -p "$SSH_PORT" "$LOGIN_USER@$TARGET_IP" "export USE_SUDO_PASSWORD=\"$USE_SUDO_PASSWORD\"; export SUDO_PASSWORD=\"$SUDO_PASSWORD\"; export SSH_PUB_KEY=\"\$(cat ~/ids_monitor.pub)\"; bash ~/setup_ids_monitor.sh && rm ~/setup_ids_monitor.sh ~/ids_monitor.pub"
        
    # Test connection with the new user
    log_progress "Testing connection with the monitoring user..."
    
    # Create a temporary file for SSH debug output
    local SSH_DEBUG_LOG=$(mktemp)
    
    # Test SSH connection and capture output
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$(get_config ssh_connect_timeout)" -i "$SSH_KEY_PATH" -p "$SSH_PORT" -v "$REMOTE_USER@$TARGET_IP" "echo 'SSH connection successful!'; exit" 2>&1 | tee "$SSH_DEBUG_LOG"
    
    # Check SSH exit status (first command in pipeline)
    local SSH_EXIT_STATUS=${PIPESTATUS[0]}
    
    if [ $SSH_EXIT_STATUS -eq 0 ]; then
        log_success "Monitoring user setup successful!"
        rm -f "$SSH_DEBUG_LOG"
    else
        log_error "Failed to connect with the monitoring user."
        log_info "This could be due to:"
        log_info "  1. SSH key authentication issues"
        log_info "  2. Incorrect permissions on the authorized_keys file"
        log_info "  3. SSH configuration on the target device"
        echo ""
        log_info "Debug information from SSH connection attempt:"
        cat "$SSH_DEBUG_LOG" 2>/dev/null || echo "Could not read debug log"
        echo ""
        log_error "Please check the SSH configuration manually."
        rm -f "$SSH_DEBUG_LOG"
        exit 1
    fi
}

# Update device in database with enrollment info
update_device_in_database() {
    log_progress "Updating device enrollment status in database..."
    
    # Get the correct database path
    local DB_PATH="$(get_config db_path)"
    # Prepend repo root if path is relative
    [[ "$DB_PATH" != /* ]] && DB_PATH="$(get_repo_root)/$DB_PATH"
    
    execute_sqlite "SELECT id FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH" > /tmp/device_id.txt
    DEVICE_ID=$(cat /tmp/device_id.txt)
    rm -f /tmp/device_id.txt
    
    if [ -z "$DEVICE_ID" ]; then
        log_warn "Device with IP $TARGET_IP not found in the database"
        log_info "Please add the device through the web interface first, then run this enrollment script"
        return 1
    fi
    
    # Temporarily disable exit on error to capture the actual failure
    set +e
    execute_sqlite "UPDATE devices SET hostname = '$HOSTNAME', os_info = '$OS_INFO', needs_reenrollment = 0 WHERE id = $DEVICE_ID;" "$DB_PATH"
    local update_result=$?
    set -e
    
    if [ $update_result -eq 0 ]; then
        log_success "Device enrollment completed successfully"
        log_info "Hostname: $HOSTNAME"
        log_info "OS: $OS_INFO"
        return 0
    else
        log_warn "Failed to update device enrollment status (exit code: $update_result)"
        log_info "Device is enrolled and functional, but database status may not reflect this"
        log_info "You can manually verify in the web interface"
        return 0  # Don't fail enrollment just because DB update failed
    fi
}

register_with_server() {
    log_progress "Registering device with IDS server..."
    
    # Prepare SSH command for the monitoring user
    MONITOR_SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=\"$(get_config ssh_connect_timeout)\" -i \"$SSH_KEY_PATH\" -p \"$SSH_PORT\" $REMOTE_USER@\"$TARGET_IP\""
    
    # Get device information
    HOSTNAME=$(eval "$MONITOR_SSH_CMD \"hostname\"")
    OS_INFO=$(eval "$MONITOR_SSH_CMD \"cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\\\"'\"")

    log_info "Device information:"
    log_info "  IP: $TARGET_IP"
    log_info "  Hostname: $HOSTNAME"
    log_info "  OS: $OS_INFO"
    log_info "  User: $REMOTE_USER"
    log_info "  Group: $REMOTE_GROUP"
    
    # Update the device enrollment status in the database
    update_device_in_database
    
    log_success "Device registered successfully!"
}

# Main execution
log_section "Device Info"
log_info "Target IP: $TARGET_IP"
log_info "Remote User: $REMOTE_USER"
log_info "Remote Group: $REMOTE_GROUP"
log_info "SSH Key: $SSH_KEY_PATH"

setup_remote_device
register_with_server

# Ensure monitoring service is configured and running for this device
# Determine device ID from database to target the right service instance
DB_PATH="$(get_config db_path)"
[[ "$DB_PATH" != /* ]] && DB_PATH="$(get_repo_root)/$DB_PATH"
DEVICE_ID=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '$TARGET_IP' AND status != 'deleted' LIMIT 1;" "$DB_PATH" 2>/dev/null || echo "")

if [ -n "$DEVICE_ID" ]; then
    SERVICE_NAME="agentless-monitor@${DEVICE_ID}.service"
    SETUP_MONITORING_SCRIPT="$SCRIPT_DIR/../setup-monitoring.sh"

    # If the service instance is already enabled or active, restart it to pick up changes
    if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1 || systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        log_info "Restarting monitoring service: $SERVICE_NAME"
        if sudo systemctl restart "$SERVICE_NAME"; then
            log_success "Monitoring service restarted"
        else
            log_warn "Failed to restart $SERVICE_NAME"
        fi
    else
        # Otherwise, run setup-monitoring.sh to create/enable the service
        if [ -f "$SETUP_MONITORING_SCRIPT" ]; then
            log_info "Monitoring service not found; running setup-monitoring.sh"
            if sudo bash "$SETUP_MONITORING_SCRIPT"; then
                log_success "Monitoring services configured"
            else
                log_warn "setup-monitoring.sh encountered errors"
            fi
        else
            log_warn "setup-monitoring.sh not found at $SETUP_MONITORING_SCRIPT"
            log_info "You may need to run it manually to start monitoring services."
        fi
    fi
else
    log_warn "Could not determine device ID; skipping monitoring service restart/setup"
fi

log_info "You can now monitor this device through your IDS dashboard."
log_section "Important Credentials"
log_info "SSH User: $REMOTE_USER"
log_info "SSH Group: $REMOTE_GROUP"
log_info "SSH Key: $SSH_KEY_PATH"
log_success "Device enrollment completed successfully!"
