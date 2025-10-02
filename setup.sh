#!/bin/bash

set -e

# Source the logging library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"
source "$SCRIPT_DIR/lib/logging.sh"

log_section "AgentLess IDS Setup"
log_info "This script will install all required dependencies and set up the AgentLess web application."

# Function to check if command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Configuration
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$APP_DIR/data"
LOG_DIR="$APP_DIR/logs"
SCRIPT_DIR="$APP_DIR/scripts"

# Create necessary directories
log_progress "Creating required directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$APP_DIR/tmp"
log_success "Directories created successfully"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  log_warn "Running as root. Consider running as a regular user with sudo privileges."
fi

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME=$NAME
  OS_VERSION=$VERSION_ID
  OS_ID=$ID
else
  handle_error "Cannot detect operating system" 1
fi

log_info "Detected OS: $OS_NAME $OS_VERSION"

# Install dependencies based on OS
log_section "System Dependencies"

case $OS_ID in
  ubuntu|debian)
    log_progress "Installing dependencies for Ubuntu/Debian..."
    sudo apt update
    sudo apt install -y \
      build-essential \
      git \
      golang-go \
      sqlcipher \
      libsqlcipher-dev \
      xxd \
      auditd \
      openssh-client \
      openssh-server \
      cron \
      curl \
      jq
    ;;
  fedora|rhel|centos|rocky|almalinux)
    log_progress "Installing dependencies for Fedora/RHEL/CentOS/Rocky/AlmaLinux..."
    
    # Enable EPEL repository for RHEL-based systems (needed for some packages)
    if [[ "$OS_ID" =~ ^(rhel|centos|rocky|almalinux)$ ]]; then
      if ! rpm -q epel-release >/dev/null 2>&1; then
        log_progress "Installing EPEL repository..."
        if [[ "$OS_ID" == "rhel" && "$OS_VERSION" =~ ^[89] ]]; then
          # RHEL 8/9
          sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_VERSION%%.*}.noarch.rpm || true
        elif [[ "$OS_ID" =~ ^(centos|rocky|almalinux)$ ]]; then
          # CentOS/Rocky/AlmaLinux
          sudo dnf install -y epel-release || true
        fi
      fi
    fi
    
    # Use dnf for newer systems, fallback to yum for older ones
    if command -v dnf >/dev/null 2>&1; then
      log_info "Using dnf package manager..."
      sudo dnf install -y \
        gcc \
        git \
        golang \
        sqlcipher \
        sqlcipher-devel \
        vim-common \
        audit \
        openssh-clients \
        openssh-server \
        cronie \
        curl \
        jq
    elif command -v yum >/dev/null 2>&1; then
      log_info "Using yum package manager..."
      sudo yum install -y \
        gcc \
        git \
        golang \
        sqlcipher \
        sqlcipher-devel \
        vim-common \
        audit \
        openssh-clients \
        openssh-server \
        cronie \
        curl \
        jq
    else
      handle_error "No package manager found (dnf/yum)" 1
    fi
    ;;
  *)
    log_warn "Unsupported OS: $OS_ID"
    log_info "Please install the following packages manually:"
    log_info "- Go (1.24 or later)"
    log_info "- SQLCipher"
    log_info "- xxd (vim-common)"
    log_info "- auditd"
    log_info "- OpenSSH client and server"
    log_info "- cron"
    log_info "- curl"
    log_info "- jq"
    ;;
esac

# Check if Go is installed
log_progress "Checking Go installation..."
if ! command -v go &> /dev/null; then
  handle_error "Go is not installed or not in PATH. Please install Go 1.24 or later" 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
log_success "Detected Go version: $GO_VERSION"

# Compare versions (simple check)
if [[ "$GO_VERSION" < "1.24" ]]; then
  log_warn "Go version $GO_VERSION is older than the recommended version (1.24)"
  log_warn "Some features may not work correctly"
fi

# Check if SQLCipher is installed
log_progress "Checking SQLCipher installation..."
if ! command -v sqlcipher &> /dev/null; then
  handle_error "SQLCipher is not installed or not in PATH. Please install SQLCipher" 1
fi
log_success "SQLCipher is installed"

# Set up Go environment if needed
if [ -z "$GOPATH" ]; then
  log_progress "Setting up Go environment..."
  export GOPATH="$HOME/go"
  mkdir -p "$GOPATH"
  
  # Add to .profile if not already there
  if ! grep -q "export GOPATH=" "$HOME/.profile" 2>/dev/null; then
    echo 'export GOPATH="$HOME/go"' >> "$HOME/.profile"
    echo 'export PATH="$PATH:$GOPATH/bin"' >> "$HOME/.profile"
    log_success "Go environment configured"
  fi
fi

# Create .env file if it doesn't exist
log_section "Application Configuration"
if [ ! -f "$APP_DIR/.env" ]; then
  log_progress "Creating default .env file..."
  
  # Generate a secure random key for session
  SESSION_KEY=$(openssl rand -hex 32)
  
  # Generate a secure random key for database encryption
  DB_KEY=$(openssl rand -hex 32)
  
  cat > "$APP_DIR/.env" << EOF
# Agent< Web config
PORT=8443
CERT_FILE=certs/server.crt
KEY_FILE=certs/server.key
DB_PATH=data/site.db
DB_ENCRYPTION_KEY=$DB_KEY
SESSION_SECRET=$SESSION_KEY
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
EOF
  log_success "Created .env file with secure random keys"
  log_warn "Please change the default admin password in the .env file"
fi

# Initialize the database directory
if [ ! -f "$DATA_DIR/site.db" ]; then
  log_progress "Initializing database directory..."
  mkdir -p "$DATA_DIR"
    touch "$DATA_DIR/site.db"
  
  # Set appropriate permissions
  chmod 700 "$DATA_DIR"
  chmod 600 "$DATA_DIR/site.db"
  log_success "Database directory initialized"
fi

# Make scripts executable
log_progress "Setting script permissions..."
chmod +x "$SCRIPT_DIR"/*.sh
log_success "Script permissions set"

# Install Go dependencies
log_section "Building Application"
log_progress "Installing Go dependencies..."
cd "$APP_DIR"
go mod download
if [ $? -ne 0 ]; then
  handle_error "Failed to download Go dependencies" 1
fi
log_success "Go dependencies installed"

# Build the application
log_progress "Building the application..."
go build -o agentless
if [ $? -ne 0 ]; then
  handle_error "Failed to build the application" 1
fi
log_success "Application built successfully"

# Set up SSH keys for monitoring if they don't exist
log_section "SSH Configuration"
if [ ! -f "$HOME/.ssh/ids_monitoring_key" ]; then
  log_progress "Generating SSH keys for monitoring..."
  ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/ids_monitoring_key" -N "" -C "ids_monitoring"
  chmod 600 "$HOME/.ssh/ids_monitoring_key"
  chmod 644 "$HOME/.ssh/ids_monitoring_key.pub"
  log_success "SSH keys generated successfully"
fi

# Set up HTTPS certificates if they don't exist
log_section "SSL Certificate Generation"
CERT_DIR="$APP_DIR/certs"
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
  log_progress "Generating self-signed SSL certificates for HTTPS..."
  mkdir -p "$CERT_DIR"
  
  # Get the hostname/IP for the certificate
  HOSTNAME=$(hostname -f 2>/dev/null || hostname)
  LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -n1)
  
  # Create certificate configuration file
  cat > "$CERT_DIR/cert.conf" << EOF
[req]
default_bits = 4096
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C=US
ST=State
L=City
O=Agent< IDS
OU=None
CN=$HOSTNAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $HOSTNAME
IP.1 = 127.0.0.1
EOF
  
  # Add local IP to certificate if detected
  if [ -n "$LOCAL_IP" ]; then
    echo "IP.2 = $LOCAL_IP" >> "$CERT_DIR/cert.conf"
  fi
  
  # Generate private key
  openssl genrsa -out "$CERT_DIR/server.key" 4096
  
  # Generate certificate signing request and self-signed certificate
  openssl req -new -x509 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -days 365 -config "$CERT_DIR/cert.conf" -extensions v3_req
  
  # Set appropriate permissions
  chmod 600 "$CERT_DIR/server.key"
  chmod 644 "$CERT_DIR/server.crt"
  chmod 644 "$CERT_DIR/cert.conf"
  
  log_success "SSL certificates generated successfully"
  log_info "Certificate: $CERT_DIR/server.crt"
  log_info "Private key: $CERT_DIR/server.key"
  log_info "Valid for: localhost, $HOSTNAME"
  if [ -n "$LOCAL_IP" ]; then
    log_info "Also valid for IP: $LOCAL_IP"
  fi
  log_info "Valid for 365 days"
fi

# Check if audit is installed and configured
log_progress "Checking audit system..."
if command -v auditctl &> /dev/null; then
  log_success "Audit system is installed"
else
  log_warn "Audit system (auditd) is not installed or not in PATH"
  log_warn "Some monitoring features may not work correctly"
fi

# Create a systemd service file for the application
log_section "Systemd Service Setup"
if [ -d "/etc/systemd/system" ]; then
  log_progress "Creating systemd service file..."
  
  # Check if service is masked and unmask it if needed
  if systemctl is-enabled agentless.service 2>&1 | grep -q "masked"; then
    log_progress "Unmasking existing service..."
    sudo systemctl unmask agentless.service
  fi
  
  # Remove old service if it exists
  if [ -f "/etc/systemd/system/agentless.service" ]; then
    log_progress "Removing existing service file..."
    sudo rm -f "/etc/systemd/system/agentless.service"
  fi
  
  # Create new service file
  sudo bash -c "cat > /etc/systemd/system/agentless.service << EOF
[Unit]
Description=Agent< Web Application
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$APP_DIR
ExecStart=/bin/bash -c 'set -a; source $APP_DIR/.env; set +a; $APP_DIR/agentless'
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=GOPATH=$GOPATH

[Install]
WantedBy=multi-user.target
EOF"

  log_progress "Reloading systemd..."
  sudo systemctl daemon-reload
  
  log_success "Systemd service created"
  log_info "To start the service: sudo systemctl start agentless"
  log_info "To enable on boot: sudo systemctl enable agentless"
fi

log_section "Setup Complete"
log_success "Setup completed successfully!"
log_info ""
log_info "Next steps:"
log_info "  1. Update the .env file with secure credentials"
log_info "  2. Start the application directly: ./agentless"
log_info "  3. Or use systemd: sudo systemctl start agentless"
log_info "  4. Access the web interface: https://localhost:8443"
log_info ""
log_warn "Your browser will show a security warning for the self-signed certificate."
log_info "This is normal - click 'Advanced' and 'Proceed' to continue."

if [[ "$start_now" =~ ^[Yy]$ ]]; then
  # Make sure logs directory exists
  mkdir -p "$LOG_DIR"
  
  # Check if the application was built successfully
  if [ -f "$APP_DIR/agentless" ]; then
    log_progress "Starting application directly..."
    # Run in background
    nohup "$APP_DIR/agentless" > "$LOG_DIR/app.log" 2>&1 &
    APP_PID=$!
    
    # Check if application started successfully
    sleep 2
    if ps -p $APP_PID > /dev/null; then
      log_success "Application started! Access at: https://localhost:8443"
      log_info "  - Logs are available at: $LOG_DIR/app.log"
      log_info "  - Process ID: $APP_PID"
      log_info "  - To stop: kill $APP_PID or pkill -f agentless"
    else
      log_error "Application failed to start. Check logs at: $LOG_DIR/app.log"
    fi
  else
    log_error "Application binary not found. Build may have failed."
  fi
fi
log_info ""
log_info "For monitoring setup:"
log_info "  - Add devices through the web interface"
log_info "  - Use the enlist.sh script to configure devices"
log_info "  - Check logs in the data directory"
log_info ""
