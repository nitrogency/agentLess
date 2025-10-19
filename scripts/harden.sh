#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/config.sh"

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

# Check if running with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run with sudo."
    exit 1
fi

log_info "Starting..."

log_info "Running system updates..."
apt update && apt upgrade -y
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure -plow unattended-upgrades
log_success "System updates complete."

log_info "Installing security tools..."
apt update && apt install -y clamav clamav-daemon clamav-freshclam ufw fail2ban
log_success "Security packages installed."

log_info "Configuring ClamAV..."

# Create log directory
mkdir -p /var/log/clamav

# Configure freshclam (disable Example line)
if [ -f /etc/clamav/freshclam.conf ]; then
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true
elif [ -f /etc/freshclam.conf ]; then
    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null || true
fi

# Configure clamd (disable Example line)
if [ -f /etc/clamav/clamd.conf ]; then
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true
elif [ -f /etc/clamd.conf ]; then
    sed -i 's/^Example/#Example/' /etc/clamd.conf 2>/dev/null || true
fi

# Stop freshclam service before manual update (avoid log file lock conflict)
if systemctl is-active clamav-freshclam >/dev/null 2>&1; then
    log_info "Stopping freshclam service temporarily for initial database update..."
    systemctl stop clamav-freshclam
fi

# Update virus definitions (this MUST complete before starting daemon)
log_info "Updating ClamAV virus definitions (this may take a few minutes)..."
if freshclam; then
    log_success "Virus definitions updated successfully"
else
    log_warn "freshclam update failed, trying to continue anyway"
fi

# Wait a moment for files to settle
sleep 2

# Enable and start freshclam service for automatic updates
log_info "Starting freshclam service for automatic updates..."
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true

# Enable and start ClamAV daemon
log_info "Starting ClamAV daemon..."
systemctl enable clamav-daemon 2>/dev/null || true
systemctl start clamav-daemon 2>/dev/null || log_warn "clamav-daemon may need manual start after database update completes"

# Set up log file permissions
if [ -f /var/log/clamav/clamav.log ]; then
    chmod 644 /var/log/clamav/clamav.log
else
    touch /var/log/clamav/clamav.log
    chmod 644 /var/log/clamav/clamav.log
fi

log_success "ClamAV configured and running."

# Install systemd timer for daily scans
log_info "Configuring daily ClamAV scans via systemd timer..."

# Get the script directory and project root
HARDEN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$HARDEN_SCRIPT_DIR")"

# Install systemd service and timer files
if [ -f "$PROJECT_ROOT/systemd/agentless-clamav-scan.service" ]; then
    cp "$PROJECT_ROOT/systemd/agentless-clamav-scan.service" /etc/systemd/system/
    log_info "Installed ClamAV scan service"
else
    log_error "agentless-clamav-scan.service not found at $PROJECT_ROOT/systemd/"
    exit 1
fi

if [ -f "$PROJECT_ROOT/systemd/agentless-clamav-scan.timer" ]; then
    cp "$PROJECT_ROOT/systemd/agentless-clamav-scan.timer" /etc/systemd/system/
    log_info "Installed ClamAV scan timer"
else
    log_error "agentless-clamav-scan.timer not found at $PROJECT_ROOT/systemd/"
    exit 1
fi

# Reload systemd and enable timer
systemctl daemon-reload
systemctl enable agentless-clamav-scan.timer
systemctl start agentless-clamav-scan.timer

log_success "Daily ClamAV scans configured (runs at 2:00 AM daily)"
log_info "Scan logs: /var/log/clamav/clamav.log"
log_info "Quarantine directory: /var/log/clamav/quarantine"
log_info "Check timer status: systemctl status agentless-clamav-scan.timer"
log_info "Run manual scan: systemctl start agentless-clamav-scan.service"

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
if timeout 10 systemctl restart sshd 2>/dev/null; then
    log_info "SSH service reloaded successfully (sshd)"
elif timeout 10 systemctl restart ssh 2>/dev/null; then
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

if [ ! -d "$APP_DIR" ]; then
    log_error "Agent< not found at $APP_DIR"
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

# Load the rules (allow non-zero exit on "No change")
augenrules --load || true

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

# Enroll localhost for self-monitoring
log_section "Localhost Self-Monitoring"
log_info "Enrolling localhost to monitor the IDS server itself..."

# Get project root and database path
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DB_PATH="$PROJECT_ROOT/data/site.db"

if [ ! -f "$DB_PATH" ]; then
    log_error "Database not found at $DB_PATH"
    log_error "Please run setup.sh first"
    exit 1
fi

# Load database encryption key
if [ -f "/etc/agentless/secrets.env" ]; then
    source /etc/agentless/secrets.env
fi

# Get hostname and OS info
HOSTNAME=$(hostname)
OS_INFO=$(cat /etc/os-release | grep PRETTY_NAME | cut -d '=' -f 2 | tr -d '"')

# Add agentless to adm group for audit log access
log_progress "Adding agentless user to adm group for log access..."
if ! groups agentless | grep -q '\badm\b'; then
    usermod -a -G adm agentless
    log_success "User 'agentless' added to adm group"
else
    log_info "User 'agentless' already in adm group"
fi

# Check if localhost already exists in database
EXISTING_LOCALHOST=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '127.0.0.1' AND status != 'deleted' LIMIT 1;" "$DB_PATH" 2>/dev/null || echo "")

if [ -n "$EXISTING_LOCALHOST" ]; then
    log_info "Localhost already enrolled (Device ID: $EXISTING_LOCALHOST)"
    LOCALHOST_ID="$EXISTING_LOCALHOST"
else
    # Insert localhost as a device
    log_progress "Adding localhost to database..."
    execute_sqlite "INSERT INTO devices (name, type, status, ip_address, ssh_user, ssh_key_path, ssh_port, hostname, os_info, os_type, ssh_group, setup_user, audit_arch, audit_ruleset) VALUES ('Localhost (Monitor Server)', 'server', 'online', '127.0.0.1', 'agentless', '/opt/agentless/.ssh/monitor', 22, '$HOSTNAME', '$OS_INFO', 'linux', 'agentless', 'root', 'x64', 'audit_default.rules');" "$DB_PATH"
    
    LOCALHOST_ID=$(execute_sqlite "SELECT id FROM devices WHERE ip_address = '127.0.0.1' AND status != 'deleted' LIMIT 1;" "$DB_PATH")
    log_success "Localhost enrolled as Device ID: $LOCALHOST_ID"
fi

# Set up systemd service for localhost monitoring
log_progress "Configuring localhost monitoring service..."
SERVICE_NAME="agentless-monitor@$LOCALHOST_ID.service"

if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    log_info "Restarting monitoring service: $SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
else
    log_info "Starting monitoring service: $SERVICE_NAME"
    
    # Install monitoring service template if not present
    if [ ! -f "/etc/systemd/system/agentless-monitor@.service" ]; then
        if [ -f "$PROJECT_ROOT/systemd/agentless-monitor@.service.template" ]; then
            sed -e "s|__REPO_ROOT__|$PROJECT_ROOT|g" \
                -e "s|__MONITOR_SCRIPT__|$PROJECT_ROOT/scripts/start-monitoring.sh|g" \
                "$PROJECT_ROOT/systemd/agentless-monitor@.service.template" | tee /etc/systemd/system/agentless-monitor@.service >/dev/null
            systemctl daemon-reload
        fi
    fi
    
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl start "$SERVICE_NAME" 2>/dev/null || true
fi

if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    log_success "Localhost monitoring service running"
    log_info "View logs: journalctl -u $SERVICE_NAME -f"
    log_info "Check status: systemctl status $SERVICE_NAME"
else
    log_warn "Monitoring service may not have started correctly"
fi

log_success "Localhost self-monitoring configured (using standard monitoring.sh)"
log_info "Localhost logs will appear in the web dashboard automatically"

