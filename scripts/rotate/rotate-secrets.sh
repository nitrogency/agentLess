#!/bin/bash

# Agent< Secret Rotation Script
# Rotates SESSION_SECRET while preserving DB_ENCRYPTION_KEY

set -e

# Source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Setup cleanup and interrupt handling
setup_cleanup_trap
setup_interrupt_trap "rotate-secrets.sh"

# Configuration
SECRETS_FILE="/etc/agentless/secrets.env"
BACKUP_DIR="/etc/agentless/backups"
APP_SERVICE="agentless"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
  handle_error "This script must be run as root or with sudo" 1
fi

log_section "Agent< Secret Rotation"
log_warn "This will rotate SESSION_SECRET"
log_warn "All active sessions will be invalidated"
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

# Store DB_ENCRYPTION_KEY
OLD_DB_KEY="$DB_ENCRYPTION_KEY"

if [ -z "$OLD_DB_KEY" ]; then
  handle_error "DB_ENCRYPTION_KEY not found in secrets file" 1
fi

# Generate new secrets
log_progress "Generating new secret..."
NEW_SESSION_SECRET=$(openssl rand -hex 32)
log_success "New secret generated"

# Write new secrets file
log_progress "Writing new secrets file..."
cat > "$SECRETS_FILE" << EOF
# Agent< Secrets - Rotated on $(date)
SESSION_SECRET=$NEW_SESSION_SECRET
DB_ENCRYPTION_KEY=$OLD_DB_KEY
EOF

chmod 600 "$SECRETS_FILE"
chown root:root "$SECRETS_FILE"
log_success "New secrets file written"

# Restart services
log_section "Restarting Services"

# Restart main application
log_progress "Restarting Agent< service..."
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

log_success "Secrets rotated successfully!"
echo ""
log_info "Changes made:"
log_info "  ✓ SESSION_SECRET: Rotated (all sessions invalidated)"
log_info "  ✓ DB_ENCRYPTION_KEY: Preserved (unchanged)"
echo ""
log_info "Backup location: $BACKUP_FILE"
log_info "Rotation log: $LOG_FILE"
echo ""
log_warn "Action required:"
log_warn "  - Users must log in again (sessions invalidated)"
echo ""
log_info "To verify service status:"
log_info "  sudo systemctl status $APP_SERVICE"
log_info "  sudo journalctl -u $APP_SERVICE -f"
echo ""
