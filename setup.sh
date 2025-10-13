#!/bin/bash

set -e

# Source the logging library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts"
source "$SCRIPT_DIR/lib/logging.sh"

log_section "Agent< IDS Setup"
log_info "This script will install all required dependencies and set up the application."

# Function to check if command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Configuration
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/agentless"
APP_DIR="$INSTALL_DIR"
DATA_DIR="$APP_DIR/data"
SCRIPT_DIR="$APP_DIR/scripts"

# Create agentless system user
log_progress "Creating agentless system user..."
if ! id agentless &>/dev/null; then
  sudo useradd -r -s /bin/bash -d /opt/agentless -M agentless
  log_success "User 'agentless' created"
else
  log_info "User 'agentless' already exists"
fi

# Configure passwordless sudo for agentless user
log_progress "Configuring passwordless sudo for agentless user..."
sudo bash -c 'cat > /etc/sudoers.d/agentless << "EOF"
# Allow agentless user to manage its own services and run enrollment scripts
agentless ALL=(root) NOPASSWD: /bin/systemctl start agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl stop agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl restart agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl enable agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl disable agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl daemon-reload
agentless ALL=(root) NOPASSWD: /bin/systemctl reload
agentless ALL=(root) NOPASSWD: /bin/systemctl is-enabled agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl is-active agentless-monitor@*
agentless ALL=(root) NOPASSWD: /bin/systemctl list-units
agentless ALL=(root) NOPASSWD: /usr/bin/tee /etc/systemd/system/agentless-monitor@.service
agentless ALL=(root) NOPASSWD: /opt/agentless/scripts/setup-monitoring.sh
EOF'
sudo chmod 440 /etc/sudoers.d/agentless
# Verify sudoers syntax
if sudo visudo -c; then
  log_success "Passwordless sudo configured for agentless user"
else
  log_error "Sudoers configuration syntax error"
  exit 1
fi

# Install to /opt/agentless
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
  log_progress "Installing to system directory: $INSTALL_DIR"
  
  # Create installation directory
  sudo mkdir -p "$INSTALL_DIR"
  
  # Copy all files to installation directory
  log_progress "Copying application files..."
  sudo cp -r "$SOURCE_DIR"/* "$INSTALL_DIR"/
  
  # Set ownership to current user for build process
  sudo chown -R $(whoami):$(whoami) "$INSTALL_DIR"
  
  log_success "Files copied to $INSTALL_DIR"
else
  log_info "Already in installation directory: $INSTALL_DIR"
fi

# Create necessary directories
log_progress "Creating required directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$APP_DIR/tmp"
mkdir -p "$APP_DIR/bin"

# Create system-wide log directory
log_progress "Creating system log directory..."
sudo mkdir -p /var/log/agentless
sudo chmod 755 /var/log/agentless
sudo chown agentless:agentless /var/log/agentless
log_success "Directories created successfully"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  log_warn "Running as root. Please run as a regular user with sudo privileges."
  exit 1
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

# Create systemd environment file for secrets
log_section "Secret Management"
SECRETS_DIR="/etc/agentless"
SECRETS_FILE="$SECRETS_DIR/secrets.env"

if [ ! -f "$SECRETS_FILE" ]; then
  log_progress "Creating systemd environment file for secrets..."
  
  # Create directory owned by agentless user
  sudo mkdir -p "$SECRETS_DIR"
  sudo chown agentless:agentless "$SECRETS_DIR"
  sudo chmod 700 "$SECRETS_DIR"
  
  # Generate a secure random key for session (64 characters)
  SESSION_KEY=$(openssl rand -hex 32)
  
  # Generate a secure random key for database encryption (64 characters)
  DB_KEY=$(openssl rand -hex 32)
  
  # Create secrets file with proper permissions
  sudo bash -c "cat > '$SECRETS_FILE' << EOF
# Agent< Secrets - Generated on $(date)
# Do not share this file or commit to version control
# Managed by systemd - file permissions: 600 (root:root)

# Session secret for cookie encryption (64 chars)
SESSION_SECRET=$SESSION_KEY

# Database encryption key (64 chars)
DB_ENCRYPTION_KEY=$DB_KEY

# Admin credentials (change after first login)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
EOF"
  
  # Set restrictive permissions (agentless user only)
  sudo chmod 400 "$SECRETS_FILE"
  sudo chown agentless:agentless "$SECRETS_FILE"
  
  log_success "Systemd secrets file created: $SECRETS_FILE"
  log_info "Secrets are stored securely with 400 permissions (agentless:agentless)"
else
  log_info "Secrets file already exists: $SECRETS_FILE"
fi

# Create .env file for non-secret configuration
log_progress "Creating application configuration file..."
cat > "$APP_DIR/.env" << EOF
# Agent< Configuration

# Server configuration
PORT=8443
GO_ENV=production

# SSL/TLS certificates
CERT_FILE=certs/server.crt
KEY_FILE=certs/server.key

# Database path
DB_PATH=data/site.db

EOF

chmod 644 "$APP_DIR/.env"
log_success "Configuration file created: $APP_DIR/.env"

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

# Build monitoring binaries
log_progress "Building monitoring binaries..."
mkdir -p "$APP_DIR/bin"

# Build Linux monitoring binary
log_progress "Building Linux monitoring binary (bin/monitor)..."
go build -o "$APP_DIR/bin/monitor" "$APP_DIR/scripts/linux/monitoring.go"
if [ $? -ne 0 ]; then
  log_warn "Failed to build Linux monitoring binary"
else
  chmod +x "$APP_DIR/bin/monitor"
  log_success "Linux monitoring binary built successfully"
fi

# Build Windows monitoring binary
log_progress "Building Windows monitoring binary (bin/monitor-windows)..."
go build -o "$APP_DIR/bin/monitor-windows" "$APP_DIR/scripts/windows/monitoring-windows.go"
if [ $? -ne 0 ]; then
  log_warn "Failed to build Windows monitoring binary"
else
  chmod +x "$APP_DIR/bin/monitor-windows"
  log_success "Windows monitoring binary built successfully"
fi

# Set ownership of all application files to agentless user
log_progress "Changing ownership of all application files to agentless user..."
sudo chown -R agentless:agentless "$INSTALL_DIR"
sudo chown agentless:agentless /var/log/agentless
log_success "All application files now owned by agentless user"

# Set up SSH keys for agentless user
log_section "SSH Configuration"

# Create .ssh directory for agentless user
log_progress "Creating SSH directory for agentless user..."
sudo mkdir -p /opt/agentless/.ssh
sudo chown agentless:agentless /opt/agentless/.ssh
sudo chmod 700 /opt/agentless/.ssh

# Generate SSH keys for monitoring if they don't exist
if [ ! -f "/opt/agentless/.ssh/ids_monitoring_key" ]; then
  log_progress "Generating SSH keys for agentless user..."
  sudo -u agentless ssh-keygen -t rsa -b 4096 -f /opt/agentless/.ssh/ids_monitoring_key -N "" -C "ids_monitoring"
  sudo chmod 600 /opt/agentless/.ssh/ids_monitoring_key
  sudo chmod 644 /opt/agentless/.ssh/ids_monitoring_key.pub
  log_success "SSH keys generated at /opt/agentless/.ssh/ids_monitoring_key"
else
  log_info "SSH keys already exist at /opt/agentless/.ssh/ids_monitoring_key"
fi

# Display public key for user reference
log_info "Public key for device enrollment:"
sudo cat /opt/agentless/.ssh/ids_monitoring_key.pub

# Set up HTTPS certificates if they don't exist
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
  
  # Create new service file with systemd secret management
  sudo bash -c "cat > /etc/systemd/system/agentless.service << EOF
[Unit]
Description=Agent< Web Application
After=network.target
Documentation=https://github.com/nitrogency/agentLess

[Service]
Type=simple
User=agentless
Group=agentless
WorkingDirectory=$APP_DIR

# Load secrets from systemd environment file
EnvironmentFile=$SECRETS_FILE

# Load non-secret configuration
EnvironmentFile=$APP_DIR/.env

# Additional environment variables
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=GOPATH=$GOPATH

# Execute application
ExecStart=$APP_DIR/agentless

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# ProtectHome removed - not needed for /opt installation
ReadWritePaths=$APP_DIR/data $APP_DIR/tmp /var/log/agentless

# Restart policy
Restart=on-failure
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=agentless-ids

[Install]
WantedBy=multi-user.target
EOF"

  log_progress "Reloading systemd..."
  sudo systemctl daemon-reload
  
  log_success "Systemd service created"
  
  # Enable and start the service automatically
  log_progress "Enabling service on boot..."
  sudo systemctl enable agentless
  
  log_progress "Starting service..."
  sudo systemctl start agentless
  
  # Wait a moment and check if it started successfully
  sleep 2
  if sudo systemctl is-active --quiet agentless; then
    log_success "Service started successfully!"
  else
    log_error "Service failed to start. Check status with: sudo systemctl status agentless"
  fi
fi

# Ask about export mode installation
log_section "Log Export Configuration"
log_info "The log exporter allows you to export audit logs to external log aggregation"
log_info "platforms (Elasticsearch, OpenSearch, Splunk, etc.) in JSON Lines format."
log_info "WARNING: Exporting logs causes additional DB and system load. Logs are also exported outside of the encrypted DB."
log_info "ONLY USE THIS IF YOU DON'T INTEND TO USE THE BUILT-IN WEB DASHBOARD FOR LOG VIEWING!"
read -p "Do you want to install the log exporter? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
  log_info "Running in export mode. Setting up exporter..."
  EXPORTER_INSTALLED=true
  if [ -f "$INSTALL_DIR/scripts/setup-exporter.sh" ]; then
    sudo bash "$INSTALL_DIR/scripts/setup-exporter.sh"
  else
    log_error "Export setup script not found at $INSTALL_DIR/scripts/setup-exporter.sh"
    EXPORTER_INSTALLED=false
  fi
else
  EXPORTER_INSTALLED=false
  log_info "Running in regular mode."
  log_progress "Removing export-related files..."
  
  # Remove export-related files and directories
  sudo rm -rf "$INSTALL_DIR/cmd/exporter" 2>/dev/null || true
  sudo rm -f "$INSTALL_DIR/systemd/agentless-exporter.service" 2>/dev/null || true
  sudo rm -f "$INSTALL_DIR/systemd/agentless-exporter.timer" 2>/dev/null || true
  sudo rm -f "$INSTALL_DIR/scripts/setup-exporter.sh" 2>/dev/null || true
  
  log_success "Export-related files removed"
fi
log_info ""

log_success "Setup completed successfully!"
log_info ""
log_success "Agent< installed to: $INSTALL_DIR"
log_success "The service is now running!"
log_info ""

# Clean up source directory if different from install directory
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ] && [ -d "$SOURCE_DIR" ]; then
  log_section "Cleanup"
  log_info "Removing source directory..."

  # Remove source directory
  if rm -rf "$SOURCE_DIR"; then
    log_success "Source directory removed successfully"
    log_info "Only the installation at $INSTALL_DIR remains"
  else
    log_warn "Could not remove source directory: $SOURCE_DIR"
    log_warn "You may need to remove it manually with: rm -rf $SOURCE_DIR"
  fi
  log_info ""
fi


log_info "Access the web interface: https://localhost:8443"
log_info "Your browser will show a security warning for the self-signed certificate."
log_info "This is normal - click 'Advanced' and 'Proceed' to continue."
log_info ""
log_info "Service Management:"
log_info "  - Check status: sudo systemctl status agentless"
log_info "  - View logs: sudo journalctl -u agentless -f"
log_info "  - Restart: sudo systemctl restart agentless"
log_info "  - Stop: sudo systemctl stop agentless"
log_info ""
log_info "Important locations:"
log_info "  - Installation: $INSTALL_DIR (owned by agentless)"
log_info "  - Secrets: /etc/agentless/secrets.env (agentless:agentless 400)"
log_info "  - Config: $INSTALL_DIR/.env"
log_info "  - Database: $INSTALL_DIR/data/site.db"
log_info "  - Logs: /var/log/agentless/"
log_info ""
log_info "For monitoring setup:"
log_info "  - Add devices through the web interface"
log_info "  - Enroll device: sudo -u agentless bash $INSTALL_DIR/scripts/linux/enlist.sh [options]"
log_info "  - Setup monitoring: sudo bash $INSTALL_DIR/scripts/setup-monitoring.sh"
log_info ""

if [ "$EXPORTER_INSTALLED" = "true" ]; then
  log_info "Log Exporter:"
  log_info "  - Status: systemctl status agentless-exporter.timer"
  log_info "  - Logs: journalctl -u agentless-exporter -f"
  log_info "  - Export directory: /var/log/agentless-export/"
  log_info ""
fi
