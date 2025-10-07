#!/bin/bash
#
# logging.sh - Standardized logging functions for helper scripts
# Source this file in other scripts: source "$(dirname "$0")/lib/logging.sh"
#

# ANSI color codes for enhanced output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_WHITE='\033[1;37m'
readonly COLOR_RESET='\033[0m'

# Symbols for visual feedback
readonly SYMBOL_SUCCESS="✓"
readonly SYMBOL_ERROR="✗"
readonly SYMBOL_WARNING="!"
readonly SYMBOL_INFO="i"
readonly SYMBOL_DEBUG="?"
readonly SYMBOL_PROGRESS=">"

# Log levels
readonly LOG_LEVEL_DEBUG=0
readonly LOG_LEVEL_INFO=1
readonly LOG_LEVEL_WARN=2
readonly LOG_LEVEL_ERROR=3

# Default log level (can be overridden by LOG_LEVEL environment variable)
CURRENT_LOG_LEVEL="${LOG_LEVEL:-$LOG_LEVEL_INFO}"

# Enable/disable colored output (auto-detect if terminal supports it)
if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
    USE_COLORS="${USE_COLORS:-true}"
else
    USE_COLORS="${USE_COLORS:-false}"
fi

# Internal logging function
_log() {
    local level="$1"
    local color="$2"
    local symbol="$3"
    local message="$4"
    local timestamp
    
    # Check if we should output this log level
    if [ "$level" -lt "$CURRENT_LOG_LEVEL" ]; then
        return 0
    fi
    
    # Generate timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    # Format message
    local formatted_message
    if [ "$USE_COLORS" = "true" ]; then
        formatted_message="${color}[$(printf "%-5s" "${level_name}")${COLOR_RESET} ${timestamp}] ${symbol} ${message}"
    else
        formatted_message="[$(printf "%-5s" "${level_name}") ${timestamp}] ${message}"
    fi
    
    # Output to appropriate stream
    if [ "$level" -ge "$LOG_LEVEL_ERROR" ]; then
        echo -e "$formatted_message" >&2
    else
        echo -e "$formatted_message"
    fi
}

# Debug logging (lowest priority)
log_debug() {
    local level_name="DEBUG"
    _log "$LOG_LEVEL_DEBUG" "$COLOR_PURPLE" "$SYMBOL_DEBUG" "$*"
}

# Info logging (normal output)
log_info() {
    local level_name="INFO"
    _log "$LOG_LEVEL_INFO" "$COLOR_BLUE" "$SYMBOL_INFO" "$*"
}

# Warning logging
log_warn() {
    local level_name="WARN"
    _log "$LOG_LEVEL_WARN" "$COLOR_YELLOW" "$SYMBOL_WARNING" "$*"
}

# Error logging (goes to stderr)
log_error() {
    local level_name="ERROR"
    _log "$LOG_LEVEL_ERROR" "$COLOR_RED" "$SYMBOL_ERROR" "$*"
}

# Success logging (special case of info)
log_success() {
    local level_name="INFO"
    _log "$LOG_LEVEL_INFO" "$COLOR_GREEN" "$SYMBOL_SUCCESS" "$*"
}

# Progress logging (for long-running operations)
log_progress() {
    local level_name="INFO"
    _log "$LOG_LEVEL_INFO" "$COLOR_CYAN" "$SYMBOL_PROGRESS" "$*"
}

# Section headers for better organization
log_section() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title} - 2) / 2 ))
    
    if [ "$USE_COLORS" = "true" ]; then
        echo -e "\n${COLOR_WHITE}$(printf '=%.0s' $(seq 1 $width))${COLOR_RESET}"
        echo -e "${COLOR_WHITE}$(printf "%*s" $padding "")${title}$(printf "%*s" $padding "")${COLOR_RESET}"
        echo -e "${COLOR_WHITE}$(printf '=%.0s' $(seq 1 $width))${COLOR_RESET}\n"
    else
        echo ""
        printf '=%.0s' $(seq 1 $width)
        echo ""
        printf "%*s%s%*s\n" $padding "" "$title" $padding ""
        printf '=%.0s' $(seq 1 $width)
        echo -e "\n"
    fi
}

# Progress bar for operations with known duration
show_progress() {
    local current="$1"
    local total="$2"
    local task="${3:-Processing}"
    local width=50
    
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    # Build progress bar
    local bar=""
    for ((i=0; i<completed; i++)); do
        bar="${bar}█"
    done
    for ((i=0; i<remaining; i++)); do
        bar="${bar}░"
    done
    
    if [ "$USE_COLORS" = "true" ]; then
        printf "\r${COLOR_CYAN}[%s] %3d%% (%d/%d) %s${COLOR_RESET}" "$bar" "$percentage" "$current" "$total" "$task"
    else
        printf "\r[%s] %3d%% (%d/%d) %s" "$bar" "$percentage" "$current" "$total" "$task"
    fi
    
    # New line when complete
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

# Command output logging (for debugging command execution)
log_command() {
    local cmd="$*"
    log_debug "Executing: $cmd"
    
    if [ "$CURRENT_LOG_LEVEL" -le "$LOG_LEVEL_DEBUG" ]; then
        # If debug logging is enabled, show command output
        "$@" 2>&1 | while IFS= read -r line; do
            log_debug "  > $line"
        done
        return "${PIPESTATUS[0]}"
    else
        # Otherwise, run silently
        "$@" >/dev/null 2>&1
    fi
}

# Error handling with context
handle_error() {
    local message="$1"
    local exit_code="${2:-1}"
    local context="${3:-}"
    
    if [ -n "$context" ]; then
        log_error "$message (Context: $context)"
    else
        log_error "$message"
    fi
    
    # Call cleanup if function exists
    if declare -f cleanup_temp_files >/dev/null 2>&1; then
        cleanup_temp_files
    fi
    
    exit "$exit_code"
}

# Set log level from string
set_log_level() {
    local level_string="$1"
    case "${level_string,,}" in
        "debug")
            CURRENT_LOG_LEVEL="$LOG_LEVEL_DEBUG"
            ;;
        "info")
            CURRENT_LOG_LEVEL="$LOG_LEVEL_INFO"
            ;;
        "warn"|"warning")
            CURRENT_LOG_LEVEL="$LOG_LEVEL_WARN"
            ;;
        "error")
            CURRENT_LOG_LEVEL="$LOG_LEVEL_ERROR"
            ;;
        *)
            log_warn "Unknown log level: $level_string. Using INFO."
            CURRENT_LOG_LEVEL="$LOG_LEVEL_INFO"
            ;;
    esac
}

# Get current log level as string
get_log_level() {
    case "$CURRENT_LOG_LEVEL" in
        "$LOG_LEVEL_DEBUG")
            echo "DEBUG"
            ;;
        "$LOG_LEVEL_INFO")
            echo "INFO"
            ;;
        "$LOG_LEVEL_WARN")
            echo "WARN"
            ;;
        "$LOG_LEVEL_ERROR")
            echo "ERROR"
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

# Initialize logging from environment
init_logging() {
    # Set log level from environment
    if [ -n "${LOG_LEVEL:-}" ]; then
        set_log_level "$LOG_LEVEL"
    fi
    
    # Disable colors if requested
    if [ "${NO_COLOR:-}" = "1" ] || [ "${NO_COLOR:-}" = "true" ]; then
        USE_COLORS="false"
    fi
    
    # Enable debug logging if DEBUG environment variable is set
    if [ "${DEBUG:-}" = "1" ] || [ "${DEBUG:-}" = "true" ]; then
        CURRENT_LOG_LEVEL="$LOG_LEVEL_DEBUG"
    fi
}

# Auto-initialize when sourced
init_logging
