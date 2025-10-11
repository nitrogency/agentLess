#!/bin/bash

# AgentLess IDS Secret Rotation Script
# Rotates SESSION_SECRET and INGEST_TOKEN while preserving DB_ENCRYPTION_KEY
# WARNING: DB_ENCRYPTION_KEY must NEVER be rotated as it encrypts existing data

set -e

# Source logging library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/logging.sh"

# Configuration
SECRETS_FILE="/etc/agentless/secrets.env"
BACKUP_DIR="/etc/agentless/backups"
APP_SERVICE="agentless"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
  handle_error "This script must be run as root or with sudo" 1
fi

log_section "AgentLess IDS Secret Rotation"
log_warn "This will rotate SESSION_SECRET and INGEST_TOKEN"
log_warn "All active sessions will be invalidated"
log_info "DB_ENCRYPTION_KEY will NOT be changed (must never change)"
echo ""

# Check if secrets file exists
if [ ! -f "$SECRETS_FILE" ]; then
  handle_error "Secrets file not found: $SECRETS_FILE" 1
fi

# Check if running in automatic mode
AUTO_MODE=false
if [[ "$1" == "--auto" ]]; then
  AUTO_MODE=true
  log_info "Running in automatic mode (no confirmation required)"
fi

# Confirm rotation (skip if auto mode)
if [ "$AUTO_MODE" = false ]; then
  read -p "Do you want to proceed with secret rotation? (yes/no): " -r CONFIRM
  if [[ ! "$CONFIRM" =~ ^[Yy][Ee][Ss]$ ]]; then
    log_info "Secret rotation cancelled"
    exit 0
  fi
fi

# Create backup directory
log_progress "Creating backup directory..."
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Backup current secrets
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/secrets_$TIMESTAMP.env"
log_progress "Backing up current secrets to: $BACKUP_FILE"
cp "$SECRETS_FILE" "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"
log_success "Backup created"

# Extract current values
log_progress "Reading current configuration..."
source "$SECRETS_FILE"

# Store DB_ENCRYPTION_KEY and ADMIN credentials (DO NOT ROTATE)
OLD_DB_KEY="$DB_ENCRYPTION_KEY"
OLD_ADMIN_USER="$ADMIN_USERNAME"
OLD_ADMIN_PASS="$ADMIN_PASSWORD"

if [ -z "$OLD_DB_KEY" ]; then
  handle_error "DB_ENCRYPTION_KEY not found in secrets file" 1
fi

# Generate new secrets
log_progress "Generating new secrets..."
NEW_SESSION_SECRET=$(openssl rand -hex 32)
NEW_INGEST_TOKEN=$(openssl rand -hex 32)
log_success "New secrets generated"

# Write new secrets file
log_progress "Writing new secrets file..."
cat > "$SECRETS_FILE" << EOF
# AgentLess IDS Secrets - Rotated on $(date)
# Previous backup: $BACKUP_FILE
# Do not share this file or commit to version control

# Session secret for cookie encryption (ROTATED)
SESSION_SECRET=$NEW_SESSION_SECRET

# Database encryption key (PRESERVED - never rotated)
DB_ENCRYPTION_KEY=$OLD_DB_KEY

# Ingest token for monitoring script authentication (ROTATED)
INGEST_TOKEN=$NEW_INGEST_TOKEN

# Admin credentials (preserved)
ADMIN_USERNAME=$OLD_ADMIN_USER
ADMIN_PASSWORD=$OLD_ADMIN_PASS
EOF

chmod 600 "$SECRETS_FILE"
chown root:root "$SECRETS_FILE"
log_success "New secrets file written"

# Restart services
log_section "Restarting Services"

# Restart main application
log_progress "Restarting AgentLess IDS service..."
if systemctl is-active --quiet "$APP_SERVICE"; then
  systemctl restart "$APP_SERVICE"
  sleep 2
  
  if systemctl is-active --quiet "$APP_SERVICE"; then
    log_success "Service restarted successfully"
  else
    log_error "Service failed to restart!"
    log_error "Restoring backup..."
    cp "$BACKUP_FILE" "$SECRETS_FILE"
    systemctl restart "$APP_SERVICE"
    handle_error "Rotation failed - backup restored" 1
  fi
else
  log_warn "Service was not running, starting it now..."
  systemctl start "$APP_SERVICE"
fi

# Restart monitoring services
log_progress "Restarting monitoring services..."
MONITOR_SERVICES=$(systemctl list-units --type=service --state=running --no-legend | grep 'agentless-monitor@' | awk '{print $1}')

if [ -n "$MONITOR_SERVICES" ]; then
  echo "$MONITOR_SERVICES" | while read -r service; do
    log_info "Restarting $service..."
    systemctl restart "$service" || log_warn "Failed to restart $service"
  done
  log_success "Monitoring services restarted"
else
  log_info "No monitoring services currently running"
fi

# Log rotation event
LOG_FILE="/var/log/agentless-secret-rotation.log"
log_progress "Logging rotation event..."
echo "[$(date)] Secret rotation completed successfully - Backup: $BACKUP_FILE" >> "$LOG_FILE"
chmod 600 "$LOG_FILE"

log_section "Rotation Complete"
log_success "Secrets rotated successfully!"
log_info ""
log_info "Changes made:"
log_info "  ✓ SESSION_SECRET: Rotated (all sessions invalidated)"
log_info "  ✓ INGEST_TOKEN: Rotated (monitoring scripts will use new token)"
log_info "  ✓ DB_ENCRYPTION_KEY: Preserved (unchanged)"
log_info ""
log_info "Backup location: $BACKUP_FILE"
log_info "Rotation log: $LOG_FILE"
log_info ""
log_warn "Action required:"
log_warn "  - Users must log in again (sessions invalidated)"
log_warn "  - Monitoring scripts automatically use new INGEST_TOKEN"
log_info ""
log_info "To verify service status:"
log_info "  sudo systemctl status $APP_SERVICE"
log_info "  sudo journalctl -u $APP_SERVICE -f"
echo ""
