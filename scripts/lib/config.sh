#!/bin/bash
#
# config.sh - Centralized configuration for AgentLess IDS scripts
# Source this file in other scripts: source "$(dirname "$0")/lib/config.sh"
#

# Version and project info
readonly AGENTLESS_VERSION="1.0.0"
readonly PROJECT_NAME="Agent<"

# Default values for device enrollment
readonly DEFAULT_REMOTE_USER="ids_monitor"
readonly DEFAULT_REMOTE_GROUP="ids_monitor"
readonly DEFAULT_SSH_PORT="22"
readonly DEFAULT_LOGIN_USER="root"

# Database configuration
readonly DEFAULT_DB_ENCRYPTION_KEY="default-dev-encryption-key-do-not-use-in-production"

# File paths (relative to repo root)
readonly DEFAULT_DB_PATH="data/site.db"
readonly DEFAULT_SSH_KEY_PATH="${HOME:-/root}/.ssh/ids_monitoring_key"

# System paths
readonly SYSTEMD_SYSTEM_DIR="/etc/systemd/system"
readonly SUDOERS_DIR="/etc/sudoers.d"

# Service and timer names
readonly MONITOR_SERVICE_TEMPLATE="agentless-monitor@.service"
readonly CLEANUP_SERVICE="agentless-cleanup.service"
readonly CLEANUP_TIMER="agentless-cleanup.timer"

# Audit configuration
readonly AUDIT_RULES_DIR="/etc/audit/rules.d"
readonly AUDIT_RULES_FILE="audit.rules"
readonly AUDIT_LOG_PATH="/var/log/audit/audit.log"
readonly AUDIT_RULES_SOURCE_PATH="rulesets/x64/audit_default.rules"

# Log retention settings
readonly DEFAULT_RETENTION_DAYS="30"
readonly DEFAULT_LOG_LIMIT="1000"

# Network and SSH settings
readonly DEFAULT_SSH_CONNECT_TIMEOUT="5"
readonly DEFAULT_SSH_COMMAND_TIMEOUT="10"

# Windows-specific settings
readonly DEFAULT_WINDOWS_COLLECTION_INTERVAL="30"
readonly WINDOWS_SYSMON_LOG="Microsoft-Windows-Sysmon/Operational"

# Security settings
readonly SSH_KEY_TYPE="rsa"
readonly SSH_KEY_BITS="4096"

# Environment variable mappings with defaults
get_config() {
    local key="$1"
    case "$key" in
        "remote_user")
            echo "${REMOTE_USER:-$DEFAULT_REMOTE_USER}"
            ;;
        "remote_group")
            echo "${REMOTE_GROUP:-$DEFAULT_REMOTE_GROUP}"
            ;;
        "ssh_port")
            echo "${SSH_PORT:-$DEFAULT_SSH_PORT}"
            ;;
        "login_user")
            echo "${LOGIN_USER:-$DEFAULT_LOGIN_USER}"
            ;;
        "db_encryption_key")
            echo "${DB_ENCRYPTION_KEY:-$DEFAULT_DB_ENCRYPTION_KEY}"
            ;;
        "db_path")
            echo "${DB_PATH:-$DEFAULT_DB_PATH}"
            ;;
        "ssh_key_path")
            echo "${SSH_KEY_PATH:-$DEFAULT_SSH_KEY_PATH}"
            ;;
        "retention_days")
            echo "${RETENTION_DAYS:-$DEFAULT_RETENTION_DAYS}"
            ;;
        "log_limit")
            echo "${LOG_LIMIT:-$DEFAULT_LOG_LIMIT}"
            ;;
        "ssh_connect_timeout")
            echo "${SSH_CONNECT_TIMEOUT:-$DEFAULT_SSH_CONNECT_TIMEOUT}"
            ;;
        "ssh_command_timeout")
            echo "${SSH_COMMAND_TIMEOUT:-$DEFAULT_SSH_COMMAND_TIMEOUT}"
            ;;
        "audit_rules_source_path")
            echo "${AUDIT_RULES_SOURCE_PATH:-$AUDIT_RULES_SOURCE_PATH}"
            ;;
        "windows_collection_interval")
            echo "${WINDOWS_COLLECTION_INTERVAL:-$DEFAULT_WINDOWS_COLLECTION_INTERVAL}"
            ;;
        *)
            # Allow custom config values with default
            local default="$2"
            if [ -n "$default" ]; then
                echo "$default"
            else
                echo ""
                return 1
            fi
            ;;
    esac
}

# Validate configuration values
validate_config() {
    local errors=0
    
    # Validate required directories exist or can be created
    local repo_root
    repo_root="$(get_repo_root)"
    
    if [ ! -d "$repo_root" ]; then
        log_error "Repository root not found: $repo_root"
        ((errors++))
    fi
    
    # Validate database path
    local db_path="$repo_root/$(get_config db_path)"
    local db_dir
    db_dir="$(dirname "$db_path")"
    
    if [ ! -d "$db_dir" ]; then
        log_warn "Database directory does not exist: $db_dir"
    fi
    
    # Validate SSH key path
    local ssh_key_path
    ssh_key_path="$(get_config ssh_key_path)"
    local ssh_key_dir
    ssh_key_dir="$(dirname "$ssh_key_path")"
    
    if [ ! -d "$ssh_key_dir" ]; then
        log_warn "SSH key directory does not exist: $ssh_key_dir"
    fi
    
    # Validate numeric values
    local retention_days
    retention_days="$(get_config retention_days)"
    if ! [[ "$retention_days" =~ ^[0-9]+$ ]] || [ "$retention_days" -lt 1 ]; then
        log_error "Invalid retention days: $retention_days"
        ((errors++))
    fi
    
    local ssh_port
    ssh_port="$(get_config ssh_port)"
    if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || [ "$ssh_port" -lt 1 ] || [ "$ssh_port" -gt 65535 ]; then
        log_error "Invalid SSH port: $ssh_port"
        ((errors++))
    fi
    
    return $errors
}

# Print configuration summary
print_config() {
    log_info "=== Agent< Config ==="
    log_info "Version: $AGENTLESS_VERSION"
    log_info "Remote User: $(get_config remote_user)"
    log_info "Remote Group: $(get_config remote_group)"
    log_info "SSH Port: $(get_config ssh_port)"
    log_info "SSH Key: $(get_config ssh_key_path)"
    log_info "Database: $(get_config db_path)"
    log_info "Retention: $(get_config retention_days) days"
    log_info "=================================="
}
