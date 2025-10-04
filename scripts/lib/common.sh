#!/bin/bash
#
# common.sh - Shared functions for AgentLess IDS scripts
# Source this file in other scripts: source "$(dirname "$0")/lib/common.sh"
#

# Check if a command/dependency exists
check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Missing dependency: $cmd"
        exit 1
    fi
}

# Get the directory containing the calling script
get_script_dir() {
    cd "$(dirname "${BASH_SOURCE[1]}")" && pwd
}

# Get the repository root directory
get_repo_root() {
    local dir="$(dirname "${BASH_SOURCE[1]}")"
    # Keep going up until we find go.mod (project root marker)
    while [ ! -f "$dir/go.mod" ] && [ "$dir" != "/" ]; do
        dir="$(cd "$dir/.." && pwd)"
    done
    
    if [ -f "$dir/go.mod" ]; then
        echo "$dir"
    else
        # Fallback: assume we're in scripts/ subdirectory
        cd "$(dirname "${BASH_SOURCE[1]}")/../" && pwd
    fi
}

# Check if a command exists (returns 0/1 for use in conditionals)
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Execute SQLite commands with encryption
execute_sqlite() {
    local query="$1"
    local db_path="${2:-$(get_repo_root)/data/site.db}"
    
    # Load encryption key from environment or use default
    local encryption_key="${DB_ENCRYPTION_KEY:-default-dev-encryption-key-do-not-use-in-production}"
    
    if [ ! -f "$db_path" ]; then
        log_error "Database not found: $db_path"
        return 1
    fi
    
    # Use SQLCipher with the encryption key
    # Suppress output for INSERT/UPDATE operations, preserve for SELECT
    if [[ "$query" =~ ^[[:space:]]*(INSERT|UPDATE|DELETE) ]]; then
        sqlcipher "$db_path" "PRAGMA key = '$encryption_key'; $query" > /dev/null 2>&1
    else
        # For SELECT queries, filter out the 'ok' output
        sqlcipher "$db_path" "PRAGMA key = '$encryption_key'; $query" 2>/dev/null | grep -v '^ok$'
    fi
}

# Sudo command with fallback handling
sudo_command() {
    # Try passwordless sudo first, fall back to interactive if needed
    if sudo -n "$@" 2>/dev/null; then
        return 0
    else
        sudo "$@"
    fi
}

# Safe systemctl operations with error handling
systemctl_safe() {
    local action="$1"
    shift
    local service="${1:-}"
    
    case "$action" in
        "enable-start")
            sudo systemctl enable "$service" || log_warn "Failed to enable $service"
            sudo systemctl start "$service" || log_warn "Failed to start $service"
            ;;
        "disable-stop")
            sudo systemctl stop "$service" 2>/dev/null || true
            sudo systemctl disable "$service" 2>/dev/null || true
            sudo systemctl reset-failed "$service" 2>/dev/null || true
            ;;
        "restart")
            sudo systemctl restart "$service" || log_warn "Failed to restart $service"
            ;;
        "reload")
            sudo systemctl daemon-reload || log_warn "Failed to reload systemd daemon"
            ;;
        *)
            sudo systemctl "$action" "$service" "$@"
            ;;
    esac
}

# Create secure temporary file
create_temp_file() {
    local prefix="${1:-agentless}"
    mktemp "${TMPDIR:-/tmp}/${prefix}.XXXXXX"
}

# Create secure temporary directory
create_temp_dir() {
    local prefix="${1:-agentless}"
    mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX"
}

# Validate IP address format
validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# Validate SSH key file
validate_ssh_key() {
    local key_file="$1"
    [ -f "$key_file" ] && ssh-keygen -l -f "$key_file" >/dev/null 2>&1
}

# Validate username format
validate_username() {
    local username="$1"
    [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] && [ ${#username} -le 32 ]
}

# Test SSH connection
test_ssh_connection() {
    local host="$1"
    local user="$2"
    local key="${3:-}"
    local port="${4:-22}"
    
    local ssh_opts="-o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no"
    
    if [ -n "$key" ]; then
        ssh_opts="$ssh_opts -i $key"
    fi
    
    ssh $ssh_opts -p "$port" "$user@$host" 'exit 0' 2>/dev/null
}

# Safe path quoting
safe_path() {
    printf '%q' "$1"
}

# Create user if not exists (idempotent)
create_user_if_not_exists() {
    local username="$1"
    local group="$2"
    local home_dir="${3:-/home/$username}"
    
    if ! id "$username" &>/dev/null; then
        log_info "Creating user: $username"
        sudo_command useradd -m -g "$group" -d "$home_dir" -s /bin/bash "$username"
    else
        log_info "User $username already exists"
    fi
}

# Create group if not exists (idempotent)
create_group_if_not_exists() {
    local groupname="$1"
    
    if ! getent group "$groupname" >/dev/null; then
        log_info "Creating group: $groupname"
        sudo_command groupadd "$groupname"
    else
        log_info "Group $groupname already exists"
    fi
}

# Add user to group (idempotent)
add_user_to_group() {
    local username="$1"
    local groupname="$2"
    
    if ! groups "$username" | grep -q "\b$groupname\b"; then
        log_info "Adding user $username to group $groupname"
        sudo_command usermod -a -G "$groupname" "$username"
    else
        log_info "User $username already in group $groupname"
    fi
}

# Generate random name from wordlists
generate_random_name() {
    local adjectives=("silent" "hidden" "secure" "vigilant" "watchful" "alert" "sentinel" "guardian" "monitor" "observer")
    local nouns=("hawk" "eagle" "falcon" "owl" "raven" "phoenix" "griffin" "dragon" "tiger" "lion")
    
    local adj_index=$((RANDOM % ${#adjectives[@]}))
    local noun_index=$((RANDOM % ${#nouns[@]}))
    
    echo "${adjectives[$adj_index]}_${nouns[$noun_index]}"
}

# Cleanup function for trap handling
cleanup_temp_files() {
    if [ -n "${TEMP_FILES:-}" ]; then
        rm -f $TEMP_FILES 2>/dev/null || true
    fi
    if [ -n "${TEMP_DIRS:-}" ]; then
        rm -rf $TEMP_DIRS 2>/dev/null || true
    fi
}

# Register temporary file for cleanup
register_temp_file() {
    local file="$1"
    TEMP_FILES="${TEMP_FILES:-} $file"
}

# Register temporary directory for cleanup
register_temp_dir() {
    local dir="$1"
    TEMP_DIRS="${TEMP_DIRS:-} $dir"
}

# Set up trap for cleanup
setup_cleanup_trap() {
    trap cleanup_temp_files EXIT INT TERM
}
