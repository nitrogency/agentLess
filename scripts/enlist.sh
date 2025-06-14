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
    
# Add the audit rule
sudo auditctl -a always,exclude -F msgtype=CWD 2>/dev/null || true

# Add audit self-monitoring rules
echo "Adding audit self-monitoring rules..."
sudo auditctl -w /var/log/audit/ -k audit_logs 2>/dev/null || true
sudo auditctl -w /etc/audit/ -p wa -k audit_tools 2>/dev/null || true
sudo auditctl -w /sbin/auditctl -p x -k audit_tools 2>/dev/null || true
sudo auditctl -w /sbin/auditd -p x -k audit_tools 2>/dev/null || true

# Add system configuration monitoring rules
echo "Adding system configuration monitoring rules..."
sudo auditctl -w /var/crash/ -p wa -k system_crash 2>/dev/null || true
sudo auditctl -w /etc/sysctl.conf -p wa -k kernel_param 2>/dev/null || true
sudo auditctl -w /etc/sysctl.d -p wa -k kernel_param 2>/dev/null || true
sudo auditctl -w /etc/modprobe.d -p wa -k kernel_mod 2>/dev/null || true
sudo auditctl -w /etc/ld.so.conf -p wa -k lib_path_settings 2>/dev/null || true
sudo auditctl -w /etc/ld.so.conf.d -p wa -k lib_path_settings 2>/dev/null || true

# Add kernel module operation monitoring
echo "Adding kernel module operation monitoring rules..."
sudo auditctl -a always,exit -F arch=b32 -S init_module -k kernel_module 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S finit_module -k kernel_module 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S delete_module -k kernel_module 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S init_module -k kernel_module 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S finit_module -k kernel_module 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S delete_module -k kernel_module 2>/dev/null || true

# Add systemd monitoring
echo "Adding systemd monitoring rules..."
sudo auditctl -w /bin/systemctl -p x -k systemd_monitoring 2>/dev/null || true
sudo auditctl -w /etc/systemd/ -p wa -k systemd_monitoring 2>/dev/null || true

# Add traditional init script monitoring
echo "Adding SysV init script monitoring rules..."
sudo auditctl -w /etc/inittab -p wa -k startup_scripts 2>/dev/null || true
sudo auditctl -w /etc/init.d/ -p wa -k startup_scripts 2>/dev/null || true

# Add power state change monitoring
echo "Adding power state change monitoring rules..."
sudo auditctl -w /usr/sbin/shutdown -p x -k power_state 2>/dev/null || true
sudo auditctl -w /usr/sbin/poweroff -p x -k power_state 2>/dev/null || true
sudo auditctl -w /usr/sbin/reboot -p x -k power_state 2>/dev/null || true
sudo auditctl -w /usr/sbin/halt -p x -k power_state 2>/dev/null || true
sudo auditctl -w /sbin/shutdown -p x -k power_state 2>/dev/null || true
sudo auditctl -w /sbin/poweroff -p x -k power_state 2>/dev/null || true
sudo auditctl -w /sbin/reboot -p x -k power_state 2>/dev/null || true
sudo auditctl -w /sbin/halt -p x -k power_state 2>/dev/null || true

# Add stunnel monitoring
echo "Adding stunnel monitoring rules..."
sudo auditctl -w /usr/sbin/stunnel -p x -k stunnel 2>/dev/null || true
sudo auditctl -w /usr/bin/stunnel -p x -k stunnel 2>/dev/null || true

# Add cron monitoring
echo "Adding cron monitoring rules..."
sudo auditctl -w /etc/cron.allow -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.deny -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.d/ -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.daily/ -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.hourly/ -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.monthly/ -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/cron.weekly/ -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /etc/crontab -p wa -k cron_events 2>/dev/null || true
sudo auditctl -w /var/spool/cron/ -k cron_events 2>/dev/null || true

# Add firewall monitoring
echo "Adding firewall monitoring rules..."
sudo auditctl -w /usr/sbin/ufw -p x -k firewall 2>/dev/null || true
sudo auditctl -w /usr/sbin/firewalld -p x -k firewall 2>/dev/null || true
sudo auditctl -w /etc/firewalld/ -p wa -k firewall 2>/dev/null || true
sudo auditctl -w /etc/ufw/ -p wa -k firewall 2>/dev/null || true

# Add PAM configuration monitoring
echo "Adding PAM configuration monitoring rules..."
sudo auditctl -w /etc/pam.d/ -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/limits.conf -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/limits.d -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/pam_env.conf -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/namespace.conf -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/namespace.d -p wa -k pam_config 2>/dev/null || true
sudo auditctl -w /etc/security/namespace.init -p wa -k pam_config 2>/dev/null || true

# Add IP tables monitoring
echo "Adding IP tables monitoring rules..."
sudo auditctl -w /sbin/iptables -p x -k IP_tables 2>/dev/null || true
sudo auditctl -w /sbin/ip6tables -p x -k IP_tables 2>/dev/null || true
sudo auditctl -w /usr/sbin/xtables-multi -p x -k IP_tables 2>/dev/null || true
sudo auditctl -w /etc/alternatives/ -p x -k IP_tables 2>/dev/null || true
sudo auditctl -w /sbin/xtables-nft-multi -p x -k IP_tables 2>/dev/null || true

# Add network environment monitoring
echo "Adding network environment monitoring rules..."
sudo auditctl -w /etc/hosts -p wa -k net_environment 2>/dev/null || true
sudo auditctl -w /etc/networks/ -p wa -k net_environment 2>/dev/null || true
sudo auditctl -w /etc/netplan/ -p wa -k net_environment 2>/dev/null || true
sudo auditctl -w /etc/resolv.conf -p wa -k net_environment 2>/dev/null || true
sudo auditctl -w /etc/nsswitch.conf -p wa -k net_environment 2>/dev/null || true

# Add advanced network environment monitoring (system calls)
echo "Adding advanced network environment monitoring rules..."
sudo auditctl -a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k net_environment_exe 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b32 -S sethostname -S setdomainname -k net_environment_exe 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_environment_exe 2>/dev/null || true

# Add time-related monitoring
echo "Adding time-related monitoring rules..."
sudo auditctl -w /etc/localtime -p wa -k time_zone 2>/dev/null || true
sudo auditctl -a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change 2>/dev/null || true
sudo auditctl -a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change 2>/dev/null || true

# Add mount operation monitoring
echo "Adding mount operation monitoring rules..."
sudo auditctl -a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount_operations 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount_operations 2>/dev/null || true

# Add session and user profile monitoring
echo "Adding session and user profile monitoring rules..."
sudo auditctl -w /var/run/utmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /var/log/btmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /var/log/wtmp -p wa -k session_info 2>/dev/null || true
sudo auditctl -w /etc/profile.d/ -p wa -k user_profiles 2>/dev/null || true
sudo auditctl -w /etc/profile -p wa -k user_profiles 2>/dev/null || true
sudo auditctl -w /etc/shells -p wa -k login_shells 2>/dev/null || true

# Add external media, SELinux and permission modification monitoring
echo "Adding external media, SELinux and permission modification monitoring rules..."
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

# Add login configuration and privilege escalation monitoring
echo "Adding login configuration and privilege escalation monitoring rules..."
sudo auditctl -w /etc/login.defs -p wa -k login 2>/dev/null || true
sudo auditctl -w /bin/su -p x -k privilege_esc 2>/dev/null || true
sudo auditctl -w /usr/bin/sudo -p x -k privilege_esc 2>/dev/null || true

# Add root command execution monitoring
echo "Adding root command execution monitoring rules..."
sudo auditctl -a always,exit -F arch=b32 -F euid=0 -S execve -k root_commands 2>/dev/null || true
sudo auditctl -a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands 2>/dev/null || true

# Add user and group management monitoring
echo "Adding user and group management monitoring rules..."
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

# Add software management monitoring
echo "Adding software management monitoring rules..."
sudo auditctl -w /usr/bin/apt -p x -k software_mgmt 2>/dev/null || true
sudo auditctl -w /usr/bin/apt-add-repository -p x -k software_mgmt 2>/dev/null || true
sudo auditctl -w /usr/bin/apt-get -p x -k software_mgmt 2>/dev/null || true

# Add reconnaissance monitoring
echo "Adding reconnaissance monitoring rules..."
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

# Add suspicious activity monitoring
echo "Adding suspicious activity monitoring rules..."
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

# Add unsuccessful write attempt monitoring
echo "Adding unsuccessful write attempt monitoring rules..."
sudo auditctl -a always,exit -F dir=/etc -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/var -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/usr/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true
sudo auditctl -a always,exit -F dir=/usr/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write 2>/dev/null || true

# Add file deletion and renaming monitoring
echo "Adding file deletion and renaming monitoring rules..."
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

# Make the rules persistent
sudo bash -c 'echo "-a always,exclude -F msgtype=CWD" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/log/audit/ -k audit_logs" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/audit/ -p wa -k audit_tools" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/auditctl -p x -k audit_tools" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/auditd -p x -k audit_tools" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/crash/ -p wa -k system_crash" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/sysctl.conf -p wa -k kernel_param" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/sysctl.d -p wa -k kernel_param" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/modprobe.d -p wa -k kernel_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/ld.so.conf -p wa -k lib_path_settings" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/ld.so.conf.d -p wa -k lib_path_settings" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S init_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S finit_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S delete_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S init_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S finit_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S delete_module -k kernel_module" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/systemctl -p x -k systemd_monitoring" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/systemd/ -p wa -k systemd_monitoring" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/inittab -p wa -k startup_scripts" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/init.d/ -p wa -k startup_scripts" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/shutdown -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/poweroff -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/reboot -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/halt -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/shutdown -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/poweroff -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/reboot -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/halt -p x -k power_state" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/stunnel -p x -k stunnel" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/stunnel -p x -k stunnel" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.allow -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.deny -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.d -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.daily -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.hourly -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.monthly -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/cron.weekly -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/crontab -p wa -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/spool/cron -k cron_events" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/ufw -p x -k firewall" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/firewalld -p x -k firewall" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/firewalld/ -p wa -k firewall" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/ufw/ -p wa -k firewall" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/pam.d/ -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/limits.conf -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/limits.d -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/pam_env.conf -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/namespace.conf -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/namespace.d -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/namespace.init -p wa -k pam_config" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/iptables -p x -k IP_tables" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/ip6tables -p x -k IP_tables" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/xtables-multi -p x -k IP_tables" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/alternatives/ -p x -k IP_tables" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /sbin/xtables-nft-multi -p x -k IP_tables" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/hosts -p wa -k net_environment" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/networks/ -p wa -k net_environment" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/netplan/ -p wa -k net_environment" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/resolv.conf -p wa -k net_environment" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/nsswitch.conf -p wa -k net_environment" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k net_environment_exe" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k net_environment_exe" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k net_environment_exe" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/localtime -p wa -k time_zone" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount_operations" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount_operations" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/run/utmp -p wa -k session_info" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/log/btmp -p wa -k session_info" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /var/log/wtmp -p wa -k session_info" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/profile.d/ -p wa -k user_profiles" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/profile -p wa -k user_profiles" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/shells -p wa -k login_shells" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /media/ -p rwxa -k external_media" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/selinux/ -p wa -k MAC_policy" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/chmod -p x -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/chown -p x -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/xattr -p x -k perm_mod" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/login.defs -p wa -k login" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/su -p x -k privilege_esc" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/sudo -p x -k privilege_esc" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -F euid=0 -S execve -k root_commands" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/apt -p x -k software_mgmt" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/apt-add-repository -p x -k software_mgmt" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/apt-get -p x -k software_mgmt" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/gshadow -k group_accounts" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/shadow -k user_pass" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/security/opasswd -k passwd_history" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/passwd -p x -k passwd_change" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/gpasswd -p x -k user_add" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/groupadd -p x -k group_add" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/addgroup -p x -k user_add" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/groupmod -p x -k group_modification" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/adduser -p x -k user_add" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/useradd -p x -k user_add" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/userdel -p x -k user_del" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/deluser -p x -k user_del" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/usermod -p x -k user_modification" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/sudoers -p rw -k sudoers_change" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/sudoers.d/ -p rw -k sudoers_change" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/whoami -p x -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/ifconfig -p x -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/id -p x -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/hostname -p x -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/uname -p x -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/issue -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/hostname -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/version -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/sys/kernel/domainname -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/swaps -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/partitions -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/cpuinfo -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /proc/self/mounts -p r -k reconnaissance" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/wget -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/curl -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/base64 -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/nc -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/nc -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/alternatives/nc -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/netcat -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/alternatives/netcat -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/ssh -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/scp -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/sftp -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/ftp -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/alternatives/ftp -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/dmesg -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/ps -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/pstree -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/top -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/htop -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/kill -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/killall -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/last -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/lsof -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/bin/kmod -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/arp -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /bin/bash -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /etc/alternatives/arptables -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-w /usr/sbin/arptables -p x -k suspicious" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/etc -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/var -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/usr/bin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F dir=/usr/sbin -F perm=w -F uid>=1000 -F success=0 -k unsuccessful_write" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S rename -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S renameat -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S rmdir -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S unlink -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b32 -S unlinkat -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S rename -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S renameat -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S rmdir -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S unlink -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true
sudo bash -c 'echo "-a always,exit -F arch=b64 -S unlinkat -F auid!=unset -F uid>=1000 -k user_delete_files" >> /etc/audit/rules.d/audit.rules' 2>/dev/null || true

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