#!/bin/bash
# enroll-device.sh - One-step Linux device enrollment

set -eo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/config.sh"
source "$SCRIPT_DIR/../lib/common.sh"

# Setup cleanup and interrupt handling
setup_cleanup_trap
setup_interrupt_trap "enroll-device.sh"

# Configuration
REMOTE_USER="${REMOTE_USER:-$(get_config remote_user)}"
REMOTE_GROUP="${REMOTE_GROUP:-$(get_config remote_group)}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$(get_config ssh_key_path)}"
SSH_PORT="${SSH_PORT:-$(get_config ssh_port)}"
LOGIN_USER="${LOGIN_USER:-$(get_config login_user)}"
SKIP_SSH_COPY="${SKIP_SSH_COPY:-false}"

# Initialize variables
TARGET_IP=""
# Display usage
usage() {
    cat << EOF
Usage: $0 [options] TARGET_IP

This script performs complete device enrollment in one step:
  1. Copies SSH key to target device (if needed)
  2. Sets up monitoring user and permissions
  3. Configures audit rules
  4. Registers device in database

Options:
  -u, --user USERNAME     Remote username to create (default: ids_monitor)
  -g, --group GROUPNAME   Remote group to create (default: ids_monitor)
  -k, --key KEY_PATH      Path to SSH key (default: $SSH_KEY_PATH)
  -l, --login USERNAME    Username to login with (default: root)
  -p, --port PORT         SSH port (default: 22)
  --skip-ssh-copy         Skip SSH key copy step (key already installed)
  -h, --help              Display this help message

Example:
  $0 192.168.1.100
  $0 -l admin -p 2222 192.168.1.100
  $0 --skip-ssh-copy 192.168.1.100  # If key already copied

EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            REMOTE_USER="$2"
            shift 2
            ;;
        -g|--group)
            REMOTE_GROUP="$2"
            shift 2
            ;;
        -k|--key)
            SSH_KEY_PATH="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -l|--login)
            LOGIN_USER="$2"
            shift 2
            ;;
        --skip-ssh-copy)
            SKIP_SSH_COPY=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            TARGET_IP="$1"
            shift
            ;;
    esac
done

# Validate target IP
if [ -z "$TARGET_IP" ]; then
    log_error "Target IP address is required"
    usage
fi

# Validate SSH key exists
if [ ! -f "$SSH_KEY_PATH" ]; then
    log_error "SSH key not found at $SSH_KEY_PATH"
    log_info "Generate one with: ssh-keygen -t rsa -b 4096 -f $SSH_KEY_PATH"
    exit 1
fi

if [ ! -f "${SSH_KEY_PATH}.pub" ]; then
    log_error "SSH public key not found at ${SSH_KEY_PATH}.pub"
    exit 1
fi

# Step 1: Check if SSH key authentication already works
log_progress "Step 1/2: Checking SSH key authentication..."
SSH_TEST_TIMEOUT=$(get_config ssh_connect_timeout)

if ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout="$SSH_TEST_TIMEOUT" \
    -i "$SSH_KEY_PATH" -p "$SSH_PORT" "$LOGIN_USER@$TARGET_IP" "exit" 2>/dev/null; then
    log_success "SSH key authentication already configured"
    SKIP_SSH_COPY=true
else
    log_info "SSH key authentication not configured"
fi

# Step 2: Copy SSH key if needed
if [ "$SKIP_SSH_COPY" = false ]; then
    log_progress "Step 1/2: Installing SSH key on target device..."
    log_info "You will be prompted for the password for $LOGIN_USER@$TARGET_IP"
    echo ""
    
    # Run ssh-copy-id with proper options
    if ssh-copy-id -i "${SSH_KEY_PATH}.pub" -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        "$LOGIN_USER@$TARGET_IP"; then
        log_success "SSH key successfully copied to $TARGET_IP"
        echo ""
    else
        log_error "Failed to copy SSH key to $TARGET_IP"
        log_info "Please ensure:"
        log_info "The target device is reachable"
        log_info "SSH is enabled on the target"
        log_info "Password authentication is enabled"
        log_info "User credentials are correct"
        exit 1
    fi
    
    # Verify key-based auth now works
    log_progress "Verifying SSH key authentication..."
    if ! ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout="$SSH_TEST_TIMEOUT" \
        -i "$SSH_KEY_PATH" -p "$SSH_PORT" "$LOGIN_USER@$TARGET_IP" "exit" 2>/dev/null; then
        log_error "SSH key authentication still not working after copy"
        log_info "This may indicate a configuration issue on the target device"
        exit 1
    fi
    log_success "SSH key authentication verified"
else
    log_info "Skipping SSH key copy (already configured or --skip-ssh-copy used)"
fi

# Step 3: Run the enrollment script
log_progress "Step 2/2: Configuring device and setting up monitoring..."
log_info "Running enlist.sh to complete device setup..."
echo ""

# Export variables for enlist.sh
export REMOTE_USER
export REMOTE_GROUP
export SSH_KEY_PATH
export SSH_PORT
export LOGIN_USER

# Run enlist.sh with the same parameters
if "$SCRIPT_DIR/enlist.sh" \
    --user "$REMOTE_USER" \
    --group "$REMOTE_GROUP" \
    --key "$SSH_KEY_PATH" \
    --port "$SSH_PORT" \
    --login "$LOGIN_USER" \
    "$TARGET_IP"; then
    echo ""
    log_success "Device $TARGET_IP has been successfully enrolled"
    log_info "The monitoring service will now collect audit logs automatically"
else
    log_error "Device enrollment failed during setup"
    log_info "SSH key was copied, but device configuration failed"
    exit 1
fi
