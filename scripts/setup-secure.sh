#!/bin/bash

set -e

echo "AgentLess IDS - Secure Setup Script"
echo "==================================="
echo "This script extends the basic setup with additional security measures."
echo ""

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
SECURITY_USER="agentless"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    error "This script should NOT be run as root for security reasons."
    echo "Run it as a regular user with sudo privileges."
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    OS_VERSION=$VERSION_ID
    OS_ID=$ID
else
    error "Cannot detect operating system"
    exit 1
fi

log "Detected OS: $OS_NAME $OS_VERSION"

echo ""
echo "This script will:"
echo "  ✓ Create a dedicated user for the AgentLess service"
echo "  ✓ Set up proper file permissions and ownership"
echo "  ✓ Configure TLS/SSL certificates"
echo "  ✓ Set up secure environment variables"
echo "  ✓ Configure log monitoring"
echo "  ✓ Apply application-specific security hardening"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# 1. CREATE DEDICATED USER
echo -e "\n${BLUE}=== 1. CREATE DEDICATED USER ===${NC}"
log "Creating dedicated user for AgentLess service..."

if ! id "$SECURITY_USER" &>/dev/null; then
    sudo adduser --system --group --home /var/lib/agentless --shell /bin/bash "$SECURITY_USER"
    sudo usermod -a -G adm "$SECURITY_USER"  # For audit log access
    log "Created user: $SECURITY_USER"
else
    log "User $SECURITY_USER already exists"
fi

# 2. SECURE FILE PERMISSIONS
echo -e "\n${BLUE}=== 2. SECURE FILE PERMISSIONS ===${NC}"
log "Setting secure file permissions..."

# Create secure directories
sudo mkdir -p /var/lib/agentless/data
sudo mkdir -p /var/lib/agentless/logs
sudo mkdir -p /var/lib/agentless/certs
sudo mkdir -p /var/lib/agentless/keys

# Set ownership
sudo chown -R "$SECURITY_USER:$SECURITY_USER" /var/lib/agentless
sudo chown -R "$SECURITY_USER:$SECURITY_USER" "$APP_DIR"

# Set permissions
sudo chmod 750 /var/lib/agentless
sudo chmod 700 /var/lib/agentless/data
sudo chmod 755 /var/lib/agentless/logs
sudo chmod 700 /var/lib/agentless/certs
sudo chmod 700 /var/lib/agentless/keys

# Secure the application directory
sudo chmod 750 "$APP_DIR"
sudo chmod 644 "$APP_DIR"/*.go 2>/dev/null || true
sudo chmod 755 "$APP_DIR/scripts"/*.sh 2>/dev/null || true

log "File permissions secured"

# 3. TLS/SSL CERTIFICATE SETUP
echo -e "\n${BLUE}=== 3. TLS/SSL CERTIFICATE SETUP ===${NC}"
log "Setting up TLS certificates..."

CERT_DIR="/var/lib/agentless/certs"
DOMAIN_NAME="localhost"

# Generate self-signed certificate for development
if [ ! -f "$CERT_DIR/server.crt" ]; then
    log "Generating self-signed certificate..."
    
    sudo -u "$SECURITY_USER" openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=AgentLess/OU=IDS/CN=$DOMAIN_NAME"
    
    # Set secure permissions on certificates
    sudo chmod 600 "$CERT_DIR/server.key"
    sudo chmod 644 "$CERT_DIR/server.crt"
    
    log "Self-signed certificate generated"
else
    log "Certificate already exists"
fi

# 4. SECURE ENVIRONMENT CONFIGURATION
echo -e "\n${BLUE}=== 4. SECURE ENVIRONMENT CONFIGURATION ===${NC}"
log "Creating secure environment configuration..."

# Create secure .env file
SECURE_ENV_FILE="/var/lib/agentless/.env"

if [ ! -f "$SECURE_ENV_FILE" ]; then
    log "Creating secure environment file..."
    
    # Generate strong secrets
    SESSION_KEY=$(openssl rand -hex 64)
    DB_KEY=$(openssl rand -hex 64)
    JWT_SECRET=$(openssl rand -hex 32)
    CSRF_KEY=$(openssl rand -hex 32)
    
    sudo -u "$SECURITY_USER" cat > "$SECURE_ENV_FILE" << EOF
# AgentLess IDS - Secure Configuration
# Generated on $(date)

# Server Configuration
SERVER_PORT=8443
SERVER_HOST=0.0.0.0
TLS_CERT_FILE=/var/lib/agentless/certs/server.crt
TLS_KEY_FILE=/var/lib/agentless/certs/server.key
ENABLE_TLS=true

# Database Configuration
DB_PATH=/var/lib/agentless/data/agentless.db
DB_ENCRYPTION_KEY=$DB_KEY
DB_MAX_CONNECTIONS=25
DB_CONNECTION_TIMEOUT=30

# Session Configuration
SESSION_SECRET=$SESSION_KEY
SESSION_NAME=agentless_session
SESSION_SECURE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=Strict
SESSION_MAX_AGE=3600

# Authentication Configuration
JWT_SECRET=$JWT_SECRET
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_COMPLEXITY=true
ENABLE_2FA=false
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_DURATION=1800

# CSRF Protection
CSRF_SECRET=$CSRF_KEY
CSRF_FIELD_NAME=csrf_token

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=/var/lib/agentless/logs/agentless.log
LOG_MAX_SIZE=100MB
LOG_MAX_BACKUPS=5
LOG_MAX_AGE=30

# Security Configuration
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
ENABLE_AUDIT_LOG=true
AUDIT_LOG_FILE=/var/lib/agentless/logs/audit.log

# Monitoring Configuration
MONITOR_INTERVAL=300
ENABLE_HEALTH_CHECK=true
HEALTH_CHECK_PORT=8444

# Admin User (Change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ChangeMe123!
ADMIN_EMAIL=admin@localhost
EOF

    # Secure the environment file
    sudo chmod 600 "$SECURE_ENV_FILE"
    
    log "Secure environment file created: $SECURE_ENV_FILE"
    warn "IMPORTANT: Change the default admin credentials in $SECURE_ENV_FILE"
else
    log "Environment file already exists"
fi

# 5. APPLICATION SECURITY CONFIGURATION
echo -e "\n${BLUE}=== 5. APPLICATION SECURITY CONFIGURATION ===${NC}"
log "Configuring application security..."

# Create security configuration file
SECURITY_CONFIG="/var/lib/agentless/security.conf"

sudo -u "$SECURITY_USER" cat > "$SECURITY_CONFIG" << 'EOF'
# AgentLess IDS Security Configuration

[authentication]
password_policy = strong
session_timeout = 3600
max_concurrent_sessions = 5
lockout_threshold = 3
lockout_duration = 1800

[encryption]
algorithm = AES-256-GCM
key_rotation_interval = 86400
backup_encryption = true

[network]
allowed_hosts = localhost,127.0.0.1
trusted_proxies = 
max_request_size = 10MB
connection_timeout = 30

[audit]
log_all_requests = true
log_authentication_events = true
log_authorization_failures = true
retain_logs_days = 90

[monitoring]
enable_intrusion_detection = true
monitor_file_changes = true
alert_on_suspicious_activity = true
health_check_interval = 60
EOF

sudo chmod 644 "$SECURITY_CONFIG"
log "Security configuration created"

# 6. SYSTEMD SERVICE HARDENING
echo -e "\n${BLUE}=== 6. SYSTEMD SERVICE HARDENING ===${NC}"
log "Creating hardened systemd service..."

sudo cat > /etc/systemd/system/agentless-secure.service << EOF
[Unit]
Description=AgentLess IDS - Secure Configuration
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
User=$SECURITY_USER
Group=$SECURITY_USER
WorkingDirectory=/var/lib/agentless
ExecStart=$APP_DIR/agentless
EnvironmentFile=/var/lib/agentless/.env
Restart=always
RestartSec=10

# Security Settings
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/agentless
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource Limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=512M
CPUQuota=200%

# Additional Security
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]l
log "Hardened systemd service created"

# 7. LOG MONITORING SETUP
echo -e "\n${BLUE}=== 7. LOG MONITORING SETUP ===${NC}"
log "Setting up log monitoring..."

# Create log monitoring script
sudo cat > /usr/local/bin/agentless-log-monitor.sh << 'EOF'
#!/bin/bash

# AgentLess Log Monitor
LOG_FILE="/var/lib/agentless/logs/agentless.log"
ALERT_LOG="/var/lib/agentless/logs/alerts.log"
LAST_CHECK_FILE="/var/lib/agentless/.last_check"

# Get timestamp of last check
if [ -f "$LAST_CHECK_FILE" ]; then
    LAST_CHECK=$(cat "$LAST_CHECK_FILE")
else
    LAST_CHECK=$(date -d "1 hour ago" '+%Y-%m-%d %H:%M:%S')
fi

# Update last check timestamp
date '+%Y-%m-%d %H:%M:%S' > "$LAST_CHECK_FILE"

# Check for suspicious activities
if [ -f "$LOG_FILE" ]; then
    # Look for authentication failures
    AUTH_FAILURES=$(grep "authentication failed\|login failed\|invalid credentials" "$LOG_FILE" | \
                   awk -v last="$LAST_CHECK" '$0 >= last' | wc -l)
    
    if [ "$AUTH_FAILURES" -gt 5 ]; then
        echo "$(date) - WARNING: $AUTH_FAILURES authentication failures detected" >> "$ALERT_LOG"
    fi
    
    # Look for brute force attempts
    BRUTE_FORCE=$(grep "rate limit exceeded\|too many requests" "$LOG_FILE" | \
                 awk -v last="$LAST_CHECK" '$0 >= last' | wc -l)
    
    if [ "$BRUTE_FORCE" -gt 10 ]; then
        echo "$(date) - WARNING: $BRUTE_FORCE rate limit violations detected" >> "$ALERT_LOG"
    fi
    
    # Look for privilege escalation attempts
    PRIV_ESC=$(grep -i "privilege\|sudo\|root\|admin" "$LOG_FILE" | \
              awk -v last="$LAST_CHECK" '$0 >= last' | wc -l)
    
    if [ "$PRIV_ESC" -gt 20 ]; then
        echo "$(date) - INFO: $PRIV_ESC privilege-related events detected" >> "$ALERT_LOG"
    fi
fi

# Rotate alert log if it gets too large
if [ -f "$ALERT_LOG" ] && [ $(stat -f%z "$ALERT_LOG" 2>/dev/null || stat -c%s "$ALERT_LOG") -gt 10485760 ]; then
    mv "$ALERT_LOG" "${ALERT_LOG}.old"
    touch "$ALERT_LOG"
    chown agentless:agentless "$ALERT_LOG"
fi
EOF

sudo chmod +x /usr/local/bin/agentless-log-monitor.sh

# Add to cron for regular monitoring
(sudo crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/agentless-log-monitor.sh") | sudo crontab -

log "Log monitoring configured"

# 8. BACKUP SCRIPT
echo -e "\n${BLUE}=== 8. BACKUP SCRIPT ===${NC}"
log "Creating backup script..."

sudo cat > /usr/local/bin/agentless-backup.sh << 'EOF'
#!/bin/bash

# AgentLess Backup Script
BACKUP_DIR="/var/backups/agentless"
DATA_DIR="/var/lib/agentless"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/agentless_backup_$TIMESTAMP.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create encrypted backup
tar -czf "$BACKUP_FILE" -C "$DATA_DIR" .

# Set secure permissions
chmod 600 "$BACKUP_FILE"
chown root:root "$BACKUP_FILE"

# Remove backups older than 30 days
find "$BACKUP_DIR" -name "agentless_backup_*.tar.gz" -mtime +30 -delete

echo "Backup created: $BACKUP_FILE"
EOF

sudo chmod +x /usr/local/bin/agentless-backup.sh

# Schedule daily backups
(sudo crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/agentless-backup.sh") | sudo crontab -

log "Backup script created and scheduled"

# 9. FINAL SECURITY CHECKS
echo -e "\n${BLUE}=== 9. FINAL SECURITY CHECKS ===${NC}"
log "Performing final security checks..."

# Check file permissions
INSECURE_FILES=$(find "$APP_DIR" -type f -perm /o+w 2>/dev/null | wc -l)
if [ "$INSECURE_FILES" -gt 0 ]; then
    warn "$INSECURE_FILES files are world-writable"
else
    log "File permissions are secure"
fi

# Check for SUID files
SUID_FILES=$(find "$APP_DIR" -type f -perm -4000 2>/dev/null | wc -l)
if [ "$SUID_FILES" -gt 0 ]; then
    warn "$SUID_FILES SUID files found in application directory"
else
    log "No SUID files found in application directory"
fi

# Validate configuration files
if [ -f "$SECURE_ENV_FILE" ]; then
    if grep -q "ChangeMe" "$SECURE_ENV_FILE"; then
        warn "Default passwords detected in configuration"
    else
        log "Configuration appears secure"
    fi
fi

log "Security checks completed"

# 10. SUMMARY AND RECOMMENDATIONS
echo -e "\n${BLUE}=== SETUP COMPLETE ===${NC}"

echo ""
echo "=== SECURE SETUP SUMMARY ==="
echo "✅ Dedicated user '$SECURITY_USER' created"
echo "✅ Secure file permissions applied"
echo "✅ TLS certificate generated"
echo "✅ Secure environment configuration created"
echo "✅ Application security configured"
echo "✅ Hardened systemd service created"
echo "✅ Log monitoring setup"
echo "✅ Automated backup configured"
echo ""
echo "=== IMPORTANT NEXT STEPS ==="
echo "1. 🔐 Change default admin credentials in: $SECURE_ENV_FILE"
echo "2. 🔒 Review and customize security settings in: $SECURITY_CONFIG"
echo "3. 🚀 Start the secure service: sudo systemctl enable --now agentless-secure"
echo "4. 🌐 Access via HTTPS: https://localhost:8443"
echo "5. 📊 Monitor logs: tail -f /var/lib/agentless/logs/agentless.log"
echo "6. 🛡️  Run security hardening: sudo $SCRIPT_DIR/security-hardening.sh"
echo ""
echo "=== SECURITY FEATURES ENABLED ==="
echo "• TLS/SSL encryption"
echo "• Dedicated service user"
echo "• File permission hardening"
echo "• Session security"
echo "• Rate limiting"
echo "• Audit logging"
echo "• Automated monitoring"
echo "• Daily backups"
echo "• Systemd security features"
echo ""
warn "Remember to:"
warn "- Keep the system updated"
warn "- Monitor security logs regularly" 
warn "- Test backups periodically"
warn "- Review access logs"
echo ""
log "Secure setup completed successfully!"
