#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"

SSH_CFG="/etc/ssh/sshd_config"
SSH_PORT="4222"

log_section "System Hardening Script"
log_info "Applies some security hardening measures to your monitor host."
log_info "This script assumes that:"
log_info "- You are using a separate VM/host for just monitoring purposes (only the Agent< server, no other services)."
log_info "- You haven't done any additional configuration other than running the setup script."
log_info "- You have a regular user created with sudo permissions."

read -p "Continue? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_success "Aborted by user."
    exit 1
fi


log_info "Starting..."

log_info "Running system updates..."
apt update && apt upgrade -y
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -plow unattended-upgrades
log_success "System updates complete."

log_info "Installing security tools..."
apt update && apt install -y clamav clamav-daemon ufw fail2ban
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam
log_success "Security tools installed."

log_info "Configuring SSH settings..."
log_info "SSH port will be set to: $SSH_PORT"
log_info "SSH config file: $SSH_CFG"

# Check if SSH config file exists
if [ ! -f "$SSH_CFG" ]; then
    log_error "SSH configuration file not found: $SSH_CFG"
    exit 1
fi

# Backup SSH config
cp "$SSH_CFG" "$SSH_CFG.backup.$(date +%Y%m%d_%H%M%S)"
log_info "SSH config backed up"

# Ensure options exist and are set correctly
sed -ri "
  s/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/;
  s/^\s*#?\s*Port\s+.*/Port $SSH_PORT/;
  s/^\s*#?\s*MaxAuthTries\s+.*/MaxAuthTries 3/;
  s/^\s*#?\s*X11Forwarding\s+.*/X11Forwarding no/;
" "$SSH_CFG"

# Add any missing options (only if they don't exist)
grep -q '^PermitRootLogin no' "$SSH_CFG"     || echo 'PermitRootLogin no' >> "$SSH_CFG"
grep -q "^Port $SSH_PORT" "$SSH_CFG"         || echo "Port $SSH_PORT" >> "$SSH_CFG"
grep -q '^MaxAuthTries 3' "$SSH_CFG"         || echo 'MaxAuthTries 3' >> "$SSH_CFG"
grep -q '^X11Forwarding no' "$SSH_CFG"       || echo 'X11Forwarding no' >> "$SSH_CFG"

# Remove any duplicate lines
awk '!seen[$0]++' "$SSH_CFG" > "$SSH_CFG.tmp" && mv "$SSH_CFG.tmp" "$SSH_CFG"

# Show the modified SSH settings for debugging
log_info "Current SSH settings after modification:"
grep -E "^(Port|PermitRootLogin|MaxAuthTries|X11Forwarding)" "$SSH_CFG" || log_info "No matching settings found"

# Create SSH privilege separation directory if it doesn't exist
if [ ! -d "/run/sshd" ]; then
    log_info "Creating SSH privilege separation directory"
    mkdir -p /run/sshd
fi

# Test SSH configuration before reloading
log_info "Testing SSH configuration..."
if sshd -t; then
    log_info "SSH configuration test passed"
else
    log_error "SSH configuration test failed"
    log_info "SSH configuration errors:"
    sshd -t
    log_info "Restoring backup configuration"
    cp "$SSH_CFG.backup."* "$SSH_CFG" 2>/dev/null || true
    exit 1
fi

# Reload SSH service
log_info "Reloading SSH service..."
if timeout 10 systemctl reload sshd 2>/dev/null; then
    log_info "SSH service reloaded successfully (sshd)"
elif timeout 10 systemctl reload ssh 2>/dev/null; then
    log_info "SSH service reloaded successfully (ssh)"
else
    log_info "WARNING: SSH service reload failed or timed out - continuing anyway"
    log_info "WARNING: You may need to manually restart SSH: sudo systemctl restart sshd"
fi

log_success "SSH settings configured."

log_info "Enabling firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow "$SSH_PORT"/tcp
ufw allow 8443/tcp
ufw --force enable
log_success "Firewall enabled."

log_info "Configuring Fail2ban..."

# App directory is always /opt/agentless (standard installation location)
APP_DIR="/opt/agentless"
LOG_DIR="/var/log/agentless"

if [ ! -d "$APP_DIR" ]; then
    log_error "AgentLess IDS not found at $APP_DIR"
    log_error "Please run setup.sh first to install the application"
    exit 1
fi

# Create logs directory and ensure permissions
sudo mkdir -p "$LOG_DIR"
sudo chmod 755 "$LOG_DIR"
sudo touch "$LOG_DIR/security.log"
sudo chmod 644 "$LOG_DIR/security.log"

log_info "Creating Fail2ban configuration..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[agentless-web]
enabled = true
port = 8443
filter = agentless-web
logpath = ${LOG_DIR}/security.log
maxretry = 5
bantime = 1800
EOF

log_info "Creating Fail2ban filter..."
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/agentless-web.conf << 'EOF'
[Definition]
failregex = ^.*Authentication failed from <HOST>.*$
            ^.*Invalid login attempt from <HOST>.*$
            ^.*Failed login from <HOST>.*$
            ^.*Login validation error for user .* from <HOST>:.*$
ignoreregex = ^.*Successful login from <HOST>.*$
              ^.*User logout from <HOST>.*$
EOF

systemctl enable --now fail2ban
log_success "Fail2ban configured and enabled."

log_info "Installing and configuring auditd..."

# Install auditd
apt install -y auditd audispd-plugins

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Backup existing audit rules if they exist
if [ -f /etc/audit/rules.d/audit.rules ]; then
    cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup.$(date +%Y%m%d_%H%M%S)
    log_info "Backed up existing audit rules"
fi

# Copy the default x64 audit rules
log_info "Loading default x64 audit rules..."
mkdir -p /etc/audit/rules.d

if [ -f "$PROJECT_ROOT/rulesets/x64/audit_default.rules" ]; then
    cp "$PROJECT_ROOT/rulesets/x64/audit_default.rules" /etc/audit/rules.d/audit.rules
    log_success "Loaded default audit rules from rulesets/x64/"
else
    log_error "Default audit rules not found at $PROJECT_ROOT/rulesets/x64/audit_default.rules"
    exit 1
fi

# Configure auditd daemon
log_info "Configuring auditd daemon..."
cat > /etc/audit/auditd.conf << 'EOF'
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file = 100
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

# Enable and start auditd
systemctl enable auditd
systemctl restart auditd

# Load the rules
augenrules --load

log_success "Auditd installed and configured with default rules."

log_info "Disabling unnecessary services..."

SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "bluetooth"
    "rpcbind"
    "nfs-client"
    "ypbind"
    "rsh"
    "rlogin"
    "rexec"
    "talk"
    "ntalk"
    "telnet"
    "chargen-dgram"
    "chargen-stream"
    "daytime-dgram"  
    "daytime-stream"
    "echo-dgram"
    "echo-stream"
    "tcpmux-server"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" >/dev/null 2>&1; then
        systemctl disable "$service" >/dev/null 2>&1 || true
        systemctl stop "$service" >/dev/null 2>&1 || true
        log_info "Disabled service: $service"
    fi
done

log_success "Unnecessary services disabled."

