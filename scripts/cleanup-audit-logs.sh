#!/bin/bash
# cleanup-audit-logs.sh [retention_days]
# Deletes audit_logs older than the specified number of days from the encrypted SQLite (SQLCipher) DB.
# Defaults to 30 days.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="$REPO_ROOT/data/site.db"

# Load env (DB_ENCRYPTION_KEY) if present
if [ -f "$REPO_ROOT/.env" ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$REPO_ROOT/.env" | xargs) || true
fi
DB_KEY="${DB_ENCRYPTION_KEY:-default-dev-encryption-key-do-not-use-in-production}"

RETENTION_DAYS="${1:-30}"

# Check dependency
if ! command -v sqlcipher >/dev/null 2>&1; then
  echo "Error: sqlcipher not found. Install with: sudo apt install -y sqlcipher" >&2
  exit 1
fi

# Execute cleanup
sqlcipher "$DB_PATH" "PRAGMA key = '$DB_KEY'; DELETE FROM audit_logs WHERE timestamp < datetime('now', '-$RETENTION_DAYS day');" >/dev/null 2>&1 || true

# Optional: vacuum occasionally for file size reclaim (commented to keep it light)
# sqlcipher "$DB_PATH" "PRAGMA key = '$DB_KEY'; VACUUM;" >/dev/null 2>&1 || true
