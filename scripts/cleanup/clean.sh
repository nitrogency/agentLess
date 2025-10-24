#!/bin/bash
# clean.sh [retention_days]
# Deletes audit_logs older than the specified number of days from the encrypted SQLite (SQLCipher) DB.
# Defaults to 30 days.
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Setup cleanup trap
setup_cleanup_trap

# Setup interrupt handling
setup_interrupt_trap "clean.sh"

# Configuration
RETENTION_DAYS="${1:-$(get_config retention_days)}"
REPO_ROOT="$(get_repo_root)"
DB_PATH="$REPO_ROOT/$(get_config db_path)"

log_info "Repository: $REPO_ROOT"
log_info "Database: $DB_PATH"
log_info "Retention: $RETENTION_DAYS days"

# Check dependencies
check_dependency sqlcipher

# Validate database exists
if [ ! -f "$DB_PATH" ]; then
    handle_error "Database not found at $DB_PATH"
fi

# Validate retention period
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [ "$RETENTION_DAYS" -lt 1 ]; then
    handle_error "Invalid retention period: $RETENTION_DAYS (must be positive integer)"
fi

log_progress "Deleting audit logs older than $RETENTION_DAYS days..."

# Execute cleanup query and capture result
deleted_rows=$(execute_sqlite "DELETE FROM audit_logs WHERE timestamp < datetime('now', '-$RETENTION_DAYS day'); SELECT changes();")

if [ "$deleted_rows" -gt 0 ]; then
    log_success "Deleted $deleted_rows old audit log entries"
else
    log_info "No old audit logs found to delete"
fi

log_success "Cleanup completed successfully"
