#!/bin/bash
#
# IDS Device Enrollment Script
# This script sets up a monitoring user on a target device
#

set -e

# Configuration
LOGIN_SSH_KEY_PATH="$HOME/.ssh/id_rsa"
MONITORING_SSH_KEY_PATH="$HOME/.ssh/ids_monitoring_key"
RANDOM_NAMES=false
RANDOM_KEY=false
REMOTE_USER="ids_monitor"
REMOTE_GROUP="ids_monitor"
MONITORING_SCRIPT_PATH="/opt/ids/monitoring.sh"
SERVER_PORT="22"
LOGIN_USER="root"  # Default login user

# Generate a name from wordlists
generate_random_name() {
    local adjectives=("silent" "hidden" "secure" "vigilant" "watchful" "alert" "sentinel" "guardian" "monitor" "observer")
    local nouns=("hawk" "eagle" "falcon" "owl" "raven" "phoenix" "griffin" "dragon" "tiger" "lion")
    
    local adj=${adjectives[$((RANDOM % ${#adjectives[@]}))]}
    local noun=${nouns[$((RANDOM % ${#nouns[@]}))]}
    
    echo "${adj}_${noun}"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

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
            SERVER_PORT="$2"
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
    echo "Error: Target IP address is required"
    usage
fi

# Generate random names if requested
if [ "$RANDOM_NAMES" = true ]; then
    REMOTE_USER=$(generate_random_name)
    REMOTE_GROUP=$(generate_random_name)
    echo "Generated random user: $REMOTE_USER"
    echo "Generated random group: $REMOTE_GROUP"
fi

# Validate login SSH key
if [ ! -f "$LOGIN_SSH_KEY_PATH" ]; then
    echo "Error: Login SSH key not found at $LOGIN_SSH_KEY_PATH"
    echo "Please specify a valid SSH key with -K or --login-key"
    exit 1
fi

# Check if monitoring SSH key exists, if not, generate it
if [ ! -f "$MONITORING_SSH_KEY_PATH" ]; then
    echo "Monitoring SSH key not found at $MONITORING_SSH_KEY_PATH"
    if [ "$RANDOM_KEY" = true ]; then
        echo "Generating a new SSH key pair for monitoring..."
        ssh-keygen -t rsa -b 4096 -f "$MONITORING_SSH_KEY_PATH" -N "" -C "ids_monitoring_key"
        echo "✅ Generated new monitoring SSH key at $MONITORING_SSH_KEY_PATH"
    else
        echo "Please specify a valid SSH key with -k or --key"
        exit 1
    fi
fi

# Get the monitoring public key
SSH_PUB_KEY=$(cat "${MONITORING_SSH_KEY_PATH}.pub")
if [ -z "$SSH_PUB_KEY" ]; then
    echo "Error: Could not read public key from ${MONITORING_SSH_KEY_PATH}.pub"
    exit 1
fi

# Test SSH connection to the target using the login key
echo "Testing SSH connection to $TARGET_IP..."
if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$LOGIN_SSH_KEY_PATH" -p "$SERVER_PORT" "$LOGIN_USER@$TARGET_IP" "exit" 2>/dev/null; then
    echo "Error: Could not connect to $TARGET_IP using SSH"
    echo "Please ensure that:"
    echo "  1. The target device is reachable"
    echo "  2. SSH is enabled on the target"
    echo "  3. The login user has SSH access"
    echo "  4. You have copied your SSH key to the target using:"
    echo "     ssh-copy-id -i ${LOGIN_SSH_KEY_PATH}.pub $LOGIN_USER@$TARGET_IP"
    exit 1
fi

echo "✅ SSH connection successful!"

# Set up the remote device
setup_remote_device() {
    echo "Setting up monitoring user on $TARGET_IP..."
    
    # Create a temporary script file locally
    TMP_SCRIPT_FILE=$(mktemp)
    
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

# Set up the .ssh directory
sudo mkdir -p /home/$REMOTE_USER/.ssh
echo "\$SSH_PUB_KEY" | sudo tee /home/$REMOTE_USER/.ssh/authorized_keys > /dev/null
sudo chmod 700 /home/$REMOTE_USER/.ssh
sudo chmod 600 /home/$REMOTE_USER/.ssh/authorized_keys
sudo chown -R $REMOTE_USER:$REMOTE_GROUP /home/$REMOTE_USER/.ssh

# Check if sshd_config allows PubkeyAuthentication
sudo grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config || {
    echo "Enabling PubkeyAuthentication in sshd_config..."
    sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    # If the option doesn't exist, add it
    if ! sudo grep -q "PubkeyAuthentication" /etc/ssh/sshd_config; then
        sudo bash -c 'echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config'
    fi
    # Restart SSH service
    sudo systemctl restart sshd || sudo service ssh restart
}

# Set up sudoers entry for specific commands
echo "Setting up sudoers entry for $REMOTE_USER..."
# Write the sudoers entry directly without using a variable
sudo bash -c "echo \"$REMOTE_USER ALL=(ALL) NOPASSWD: /usr/bin/netstat, /usr/bin/ss, /usr/bin/lsof, /usr/bin/ps, /usr/bin/last, /sbin/auditctl, /sbin/ausearch, /usr/bin/cat\" > /etc/sudoers.d/$REMOTE_USER"
sudo chmod 440 /etc/sudoers.d/$REMOTE_USER

# Verify the sudoers entry was created correctly
echo "Created sudoers entry in /etc/sudoers.d/$REMOTE_USER with permissions:"

# Set up audit rules, install auditd if not already installed
if ! command -v auditctl >/dev/null 2>&1; then
    echo "Installing auditd and auditctl..."
    sudo apt-get update
    sudo apt-get install -y auditd audispd-plugins
    sudo systemctl enable auditd
    sudo systemctl start auditd
fi

echo "Setting up audit rules..."
# Check if auditd service is running
sudo systemctl status auditd >/dev/null 2>&1 || {
    echo "Starting auditd service..."
    sudo systemctl enable auditd
    sudo systemctl start auditd
}
    
# Clean up any existing audit rules to prevent duplicates
echo "Cleaning up existing audit rules..."
sudo rm -f /etc/audit/rules.d/audit.rules

# Create a comprehensive audit rules file
echo "Creating comprehensive audit rules configuration..."
sudo tee /etc/audit/rules.d/audit.rules > /dev/null << 'AUDIT_EOF'
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1

# Exclude noisy CWD messages
-a always,exclude -F msgtype=CWD

# Audit self-monitoring rules
-w /var/log/audit/ -k audit_logs
-w /etc/audit/ -p wa -k audit_tools
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools

# System configuration monitoring
-w /var/crash/ -p wa -k system_crash
-w /etc/sysctl.conf -p wa -k kernel_param
-w /etc/sysctl.d -p wa -k kernel_param
-w /etc/modprobe.d -p wa -k kernel_mod
-w /etc/ld.so.conf -p wa -k lib_path_settings
-w /etc/ld.so.conf.d -p wa -k lib_path_settings

# Kernel module operations
-a always,exit -F arch=b32 -S init_module -k kernel_module
-a always,exit -F arch=b32 -S finit_module -k kernel_module
-a always,exit -F arch=b32 -S delete_module -k kernel_module
-a always,exit -F arch=b64 -S init_module -k kernel_module
-a always,exit -F arch=b64 -S finit_module -k kernel_module
-a always,exit -F arch=b64 -S delete_module -k kernel_module

# Systemd monitoring
-w /bin/systemctl -p x -k systemd_monitoring
-w /etc/systemd/ -p wa -k systemd_monitoring

# Init script monitoring
-w /etc/inittab -p wa -k startup_scripts
-w /etc/init.d/ -p wa -k startup_scripts

# Power state changes
-w /usr/sbin/shutdown -p x -k power_state
-w /usr/sbin/poweroff -p x -k power_state
-w /usr/sbin/reboot -p x -k power_state
-w /usr/sbin/halt -p x -k power_state
-w /sbin/shutdown -p x -k power_state
-w /sbin/poweroff -p x -k power_state
-w /sbin/reboot -p x -k power_state
-w /sbin/halt -p x -k power_state

# Cron monitoring
-w /etc/cron.allow -p wa -k cron_events
-w /etc/cron.deny -p wa -k cron_events
-w /etc/cron.d/ -p wa -k cron_events
-w /etc/cron.daily/ -p wa -k cron_events
-w /etc/cron.hourly/ -p wa -k cron_events
-w /etc/cron.monthly/ -p wa -k cron_events
-w /etc/cron.weekly/ -p wa -k cron_events
-w /etc/crontab -p wa -k cron_events
-w /var/spool/cron/ -k cron_events

# Network and security tools
-w /usr/bin/wget -p x -k suspicious
-w /usr/bin/curl -p x -k suspicious
-w /usr/bin/nc -p x -k suspicious
-w /bin/nc -p x -k suspicious
-w /usr/bin/ssh -p x -k suspicious

# User and privilege monitoring
-w /etc/passwd -p wa -k user_list
-w /etc/group -p wa -k user_group
-w /etc/shadow -k user_pass
-w /etc/sudoers -p rw -k sudoers_change
-w /etc/sudoers.d/ -p rw -k sudoers_change
-w /usr/bin/sudo -p x -k privilege_esc

# File deletion monitoring
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k user_delete_files
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k user_delete_files
AUDIT_EOF

# Restart audit services to apply new rules
echo "Restarting audit services..."
sudo systemctl stop auditd 2>/dev/null || true
sudo systemctl stop audit-rules.service 2>/dev/null || true

# Wait a moment for services to stop
sleep 2

# Start services in correct order
sudo systemctl start auditd
sudo systemctl enable auditd

# Force reload of audit rules
sudo auditctl -R /etc/audit/rules.d/audit.rules 2>/dev/null || true

echo "Audit rules configured successfully"

# Add audit rules for system calls
echo "Adding audit rules for system calls..."
sudo auditctl -a always,exit -F arch=b32 -S sethostname -S setdomainname -k net_environment_exe 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_environment_exe 2>/dev/null || true

# Add audit rules for time-related events
echo "Adding audit rules for time-related events..."
sudo auditctl -a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change 2>/dev/null || true
sudo auditctl -a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change 2>/dev/null || true

# Add audit rules for mount operations
echo "Adding audit rules for mount operations..."
sudo auditctl -a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount_operations 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount_operations 2>/dev/null || true

# Add audit rules for session and user profile monitoring
echo "Adding audit rules for session and user profile monitoring..."
sudo auditctl -w /var/run/utmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /var/log/btmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /var/log/wtmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /etc/profile.d/ -p wa -k user_profiles 2>/dev/null || true
sudo auditctl -w /etc/profile -p wa -k user_profiles 2>/dev/null || true
sudo auditctl -w /etc/shells -p wa -k login_shells 2>/dev/null || true

# Add audit rules for external media, SELinux and permission modification monitoring
echo "Adding audit rules for external media, SELinux and permission modification monitoring..."
sudo auditctl -w /media/ -p rwxa -k external_media 2>/dev/null || true
sudo auditctl -w /etc/selinux/ -p wa -k MAC_policy 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm_mod 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod 2>/dev/null || true
sudo auditctl -w /bin/chmod -p x -k perm_mod 2>/dev/null || true
sudo auditctl -w /bin/chown -p x -k perm_mod 2>/dev/null || true
sudo auditctl -w /usr/bin/xattr -p x -k perm_mod 2>/dev/null || true

# Add audit rules for login configuration and privilege escalation monitoring
echo "Adding audit rules for login configuration and privilege escalation monitoring..."
sudo auditctl -w /etc/login.defs -p wa -k login 2>/dev/null || true
sudo auditctl -w /bin/su -p x -k privilege_esc 2>/dev/null || true
sudo auditctl -w /usr/bin/sudo -p x -k privilege_esc 2>/dev/null || true

# Add audit rules for root command execution monitoring
echo "Adding audit rules for root command execution monitoring..."
sudo auditctl -a always,exit -F arch=b32 -F euid=0 -S execve -k root_commands 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands 2>/dev/null || true

# Add audit rules for user and group management monitoring
echo "Adding audit rules for user and group management monitoring..."
sudo auditctl -w /etc/group -p wa -k user_group 2>/dev/null || true
sudo auditctl -w /etc/passwd -p wa -k user_list 2>/dev/null || true
sudo auditctl -w /etc/gshadow -k group_accounts 2>/dev/null || true
sudo auditctl -w /etc/shadow -k user_pass 2>/dev/null || true
sudo auditctl -w /etc/security/opasswd -k passwd_history 2>/dev/null || true
sudo auditctl -w /usr/bin/passwd -p x -k passwd_change 2>/dev/null || true
sudo auditctl -w /usr/bin/gpasswd -p x -k user_add 2>/dev/null || true
sudo auditctl -w /usr/sbin/groupadd -p x -k group_add 2>/dev/null || true
sudo auditctl -w /usr/sbin/addgroup -p x -k user_add 2>/dev/null || true
sudo auditctl -w /usr/sbin/groupmod -p x -k group_modification 2>/dev/null || true
sudo auditctl -w /usr/sbin/adduser -p x -k user_add 2>/dev/null || true
sudo auditctl -w /usr/sbin/useradd -p x -k user_add 2>/dev/null || true
sudo auditctl -w /usr/sbin/userdel -p x -k user_del 2>/dev/null || true
sudo auditctl -w /usr/sbin/deluser -p x -k user_del 2>/dev/null || true
sudo auditctl -w /usr/sbin/usermod -p x -k user_modification 2>/dev/null || true
sudo auditctl -w /etc/sudoers -p rw -k sudoers_change 2>/dev/null || true
sudo auditctl -w /etc/sudoers.d/ -p rw -k sudoers_change 2>/dev/null || true

# Add audit rules for software management monitoring
echo "Adding audit rules for software management monitoring..."
sudo auditctl -w /usr/bin/apt -p x -k software_mgmt 2>/dev/null || true
sudo auditctl -w /usr/bin/apt-add-repository -p x -k software_mgmt 2>/dev/null || true
sudo auditctl -w /usr/bin/apt-get -p x -k software_mgmt 2>/dev/null || true

# Add audit rules for reconnaissance monitoring
echo "Adding audit rules for reconnaissance monitoring..."
sudo auditctl -w /usr/bin/whoami -p x -k reconnaissance 2>/dev/null || true
sudo auditctl -w /usr/sbin/ifconfig -p x -k reconnaissance 2>/dev/null || true
sudo auditctl -w /usr/bin/id -p x -k reconnaissance 2>/dev/null || true
sudo auditctl -w /bin/hostname -p x -k reconnaissance 2>/dev/null || true
sudo auditctl -w /bin/uname -p x -k reconnaissance 2>/dev/null || true
sudo auditctl -w /etc/issue -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /etc/hostname -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/version -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/sys/kernel/domainname -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/swaps -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/partitions -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/cpuinfo -p r -k reconnaissance 2>/dev/null || true
sudo auditctl -w /proc/self/mounts -p r -k reconnaissance 2>/dev/null || true

# Add audit rules for suspicious activity monitoring
echo "Adding audit rules for suspicious activity monitoring..."
sudo auditctl -w /usr/bin/wget -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/curl -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/base64 -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/nc -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /bin/nc -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /etc/alternatives/nc -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /bin/netcat -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /etc/alternatives/netcat -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/ssh -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/scp -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/sftp -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/ftp -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /etc/alternatives/ftp -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/dmesg -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/ps -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/pstree -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/top -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/htop -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/kill -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/killall -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/last -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/lsof -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/bin/kmod -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/sbin/arp -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /bin/bash -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /etc/alternatives/arptables -p x -k suspicious 2>/dev/null || true
sudo auditctl -w /usr/sbin/arptables -p x -k suspicious 2>/dev/null || true

# Add audit rules for unsuccessful write attempt monitoring
echo "Adding audit rules for unsuccessful write attempt monitoring..."
sudo auditctl -a always,exit -F dir=/etc -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/var -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/usr/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/usr/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true

# Add audit rules for file deletion and renaming monitoring
echo "Adding audit rules for file deletion and renaming monitoring..."
sudo auditctl -a always,exit -F arch=b32 -S rename -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S renameat -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S rmdir -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S unlink -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S unlinkat -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S rename -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S renameat -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S rmdir -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S unlink -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S unlinkat -F auid!=unset -F uid>=1000 -k user_delete_files 2>/dev/null || true

# Verify that audit rules are correctly configured
echo "Audit rules verification: OK"

# Restart auditd to apply changes
sudo systemctl restart auditd
echo "Audit rules configured successfully"

# Verify the authorized_keys file
echo "Verifying SSH key setup:"
sudo ls -la /home/$REMOTE_USER/.ssh/
sudo cat /home/$REMOTE_USER/.ssh/authorized_keys

echo "Remote setup completed successfully"
EOF
    
    # Make the script executable
    chmod +x "$TMP_SCRIPT_FILE"
    
    # Copy the script to the target
    scp -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -P "$SERVER_PORT" "$TMP_SCRIPT_FILE" "$LOGIN_USER@$TARGET_IP:~/setup_ids_monitor.sh"
    
    # Create a temporary file with the SSH public key
    SSH_KEY_TMP_FILE=$(mktemp)
    echo "$SSH_PUB_KEY" > "$SSH_KEY_TMP_FILE"
    
    # Copy the SSH key to the target
    scp -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -P "$SERVER_PORT" "$SSH_KEY_TMP_FILE" "$LOGIN_USER@$TARGET_IP:~/ids_monitor.pub"
    
    # Run the script on the target with a pseudo-terminal allocation
    ssh -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -t -p "$SERVER_PORT" "$LOGIN_USER@$TARGET_IP" "export USE_SUDO_PASSWORD=\"$USE_SUDO_PASSWORD\"; export SUDO_PASSWORD=\"$SUDO_PASSWORD\"; export SSH_PUB_KEY=\"\$(cat ~/ids_monitor.pub)\"; bash ~/setup_ids_monitor.sh && rm ~/setup_ids_monitor.sh ~/ids_monitor.pub"
    
    # Remove the temporary files
    rm -f "$TMP_SCRIPT_FILE" "$SSH_KEY_TMP_FILE"
    
    # Test connection with the new user
    echo "Testing connection with the monitoring user..."
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$MONITORING_SSH_KEY_PATH" -p "$SERVER_PORT" -v "$REMOTE_USER@$TARGET_IP" "echo 'SSH connection successful!'; exit" 2>&1 | tee /tmp/ssh_debug.log; then
        echo "✅ Monitoring user setup successful!"
    else
        echo "❌ Failed to connect with the monitoring user."
        echo "This could be due to:"
        echo "  1. SSH key authentication issues"
        echo "  2. Incorrect permissions on the authorized_keys file"
        echo "  3. SSH configuration on the target device"
        echo ""
        echo "Debug information from SSH connection attempt:"
        cat /tmp/ssh_debug.log
        echo ""
        echo "Trying to fix common issues..."
        
        # Try to fix common issues
        ssh -o StrictHostKeyChecking=no -i "$LOGIN_SSH_KEY_PATH" -t -p "$SERVER_PORT" "$LOGIN_USER@$TARGET_IP" "
            sudo chmod 700 /home/$REMOTE_USER/.ssh
            sudo chmod 600 /home/$REMOTE_USER/.ssh/authorized_keys
            sudo chown -R $REMOTE_USER:$REMOTE_GROUP /home/$REMOTE_USER/.ssh
            
            # Check if sshd_config allows PubkeyAuthentication
            echo \"Checking SSH server configuration...\"
            sudo grep -E 'PubkeyAuthentication|PasswordAuthentication|AuthorizedKeysFile' /etc/ssh/sshd_config
            
            # Ensure SSH server allows key authentication
            echo \"Ensuring SSH server allows key authentication...\"
            sudo sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
            sudo sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
            
            # Restart SSH service
            echo \"Restarting SSH service...\"
            sudo systemctl restart sshd || sudo service ssh restart
            
            # Try copying the key directly
            echo \"Copying the key directly...\"
            sudo bash -c 'echo \"$SSH_PUB_KEY\" > /home/$REMOTE_USER/.ssh/authorized_keys'
            sudo chmod 600 /home/$REMOTE_USER/.ssh/authorized_keys
            sudo chown $REMOTE_USER:$REMOTE_GROUP /home/$REMOTE_USER/.ssh/authorized_keys
        "
        
        # Try again with verbose output
        echo "Trying connection again with verbose output..."
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$MONITORING_SSH_KEY_PATH" -p "$SERVER_PORT" -v "$REMOTE_USER@$TARGET_IP" "echo 'SSH connection successful!'; exit" 2>&1 | tee /tmp/ssh_debug.log; then
            echo "✅ Fixed the issue! Monitoring user setup successful!"
        else
            echo "❌ Still unable to connect with the monitoring user."
            echo "Debug information from second SSH connection attempt:"
            cat /tmp/ssh_debug.log
            echo ""
            echo "Please check the SSH configuration manually."
            exit 1
        fi
    fi
}

# Register the device with the IDS server
register_with_server() {
    echo "Registering device with IDS server..."
    
    # Prepare SSH command for the monitoring user
    MONITOR_SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i \"$MONITORING_SSH_KEY_PATH\" -p \"$SERVER_PORT\" $REMOTE_USER@\"$TARGET_IP\""
    
    # Get device information
    HOSTNAME=$(eval "$MONITOR_SSH_CMD \"hostname\"")
    OS_INFO=$(eval "$MONITOR_SSH_CMD \"cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '\\\"'\"")
    
    # Here you would typically make an API call to your server to register the device
    # For demonstration purposes, we'll just echo the information
    echo "Device information:"
    echo "  IP: $TARGET_IP"
    echo "  Hostname: $HOSTNAME"
    echo "  OS: $OS_INFO"
    echo "  User: $REMOTE_USER"
    echo "  Group: $REMOTE_GROUP"
    
    # In a real implementation, you would make an HTTP request to your server API
    # curl -X POST -H "Content-Type: application/json" \
    #   -d "{\"ip\":\"$TARGET_IP\",\"hostname\":\"$HOSTNAME\",\"os\":\"$OS_INFO\",\"user\":\"$REMOTE_USER\",\"group\":\"$REMOTE_GROUP\"}" \
    #   http://your-server/api/devices
    
    echo "✅ Device registered successfully!"
}

# Main execution
echo "Starting device enrollment for $TARGET_IP..."
setup_remote_device
register_with_server

echo ""
echo "Device enrollment completed successfully!"
echo "You can now monitor this device through your IDS dashboard."
echo ""
echo "IMPORTANT: Save these credentials for future reference:"
echo "  SSH User: $REMOTE_USER"
echo "  SSH Group: $REMOTE_GROUP"
echo "  SSH Key: $MONITORING_SSH_KEY_PATH"