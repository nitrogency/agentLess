#!/bin/bash

set -e

echo "🚀 Starting Agent< Setup"
echo "===================================="
echo "This script will install all required dependencies and set up the AgentLess web application."

# Function to handle errors
handle_error() {
  echo "❌ Error: $1"
  exit 1
}

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
echo "📁 Creating required directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$APP_DIR/tmp"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo "⚠️  Warning: Running as root. Consider running as a regular user with sudo privileges."
fi

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME=$NAME
  OS_VERSION=$VERSION_ID
  OS_ID=$ID
else
  echo "❌ Error: Cannot detect operating system"
  exit 1
fi

echo "🖥️  Detected OS: $OS_NAME $OS_VERSION"

# Install dependencies based on OS
echo "📦 Installing system dependencies..."

case $OS_ID in
  ubuntu|debian)
    echo "Installing dependencies for Ubuntu/Debian..."
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
  fedora|rhel|centos)
    echo "Installing dependencies for Fedora/RHEL/CentOS..."
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
    ;;
  *)
    echo "❌ Unsupported OS: $OS_ID"
    echo "Please install the following packages manually:"
    echo "- Go (1.24 or later)"
    echo "- SQLCipher"
    echo "- xxd (vim-common)"
    echo "- auditd"
    echo "- OpenSSH client and server"
    echo "- cron"
    echo "- curl"
    echo "- jq"
    ;;
esac

# Check if Go is installed
if ! command -v go &> /dev/null; then
  echo "❌ Error: Go is not installed or not in PATH"
  echo "Please install Go 1.24 or later"
  exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "🔍 Detected Go version: $GO_VERSION"

# Compare versions (simple check)
if [[ "$GO_VERSION" < "1.24" ]]; then
  echo "⚠️  Warning: Go version $GO_VERSION is older than the recommended version (1.24)"
  echo "Some features may not work correctly"
fi

# Check if SQLCipher is installed
if ! command -v sqlcipher &> /dev/null; then
  echo "❌ Error: SQLCipher is not installed or not in PATH"
  echo "Please install SQLCipher"
  exit 1
fi

# Set up Go environment if needed
if [ -z "$GOPATH" ]; then
  echo "🔧 Setting up Go environment..."
  export GOPATH="$HOME/go"
  mkdir -p "$GOPATH"
  
  # Add to .profile if not already there
  if ! grep -q "export GOPATH=" "$HOME/.profile" 2>/dev/null; then
    echo 'export GOPATH="$HOME/go"' >> "$HOME/.profile"
    echo 'export PATH="$PATH:$GOPATH/bin"' >> "$HOME/.profile"
  fi
fi

# Create .env file if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
  echo "📝 Creating default .env file..."
  
  # Generate a secure random key for session
  SESSION_KEY=$(openssl rand -hex 32)
  
  # Generate a secure random key for database encryption
  DB_KEY=$(openssl rand -hex 32)
  
  cat > "$APP_DIR/.env" << EOF
# AgentLess Web App Configuration
PORT=8080
DB_PATH=data/site.db
DB_ENCRYPTION_KEY=$DB_KEY
SESSION_SECRET=$SESSION_KEY
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme
EOF
  echo "✅ Created .env file with secure random keys"
  echo "⚠️  Please change the default admin password in the .env file"
fi

# Initialize the database directory
if [ ! -f "$DATA_DIR/site.db" ]; then
  echo "🗄️  Initializing database directory..."
  mkdir -p "$DATA_DIR"
    touch "$DATA_DIR/site.db"
  
  # Set appropriate permissions
  chmod 700 "$DATA_DIR"
  chmod 600 "$DATA_DIR/site.db"
fi

# Make scripts executable
echo "🔧 Setting script permissions..."
chmod +x "$SCRIPT_DIR"/*.sh

# Install Go dependencies
echo "📚 Installing Go dependencies..."
cd "$APP_DIR"
go mod download
if [ $? -ne 0 ]; then
  echo "❌ Error downloading Go dependencies"
  exit 1
fi

# Build the application
echo "🔨 Building the application..."
go build -o agentless
if [ $? -ne 0 ]; then
  echo "❌ Error building the application"
    exit 1
fi

# Set up SSH keys for monitoring if they don't exist
if [ ! -f "$HOME/.ssh/ids_monitoring_key" ]; then
  echo "🔑 Generating SSH keys for monitoring..."
  ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/ids_monitoring_key" -N "" -C "ids_monitoring"
  chmod 600 "$HOME/.ssh/ids_monitoring_key"
  chmod 644 "$HOME/.ssh/ids_monitoring_key.pub"
fi

# Check if audit is installed and configured
if command -v auditctl &> /dev/null; then
  echo "✅ Audit system is installed"
else
  echo "⚠️  Warning: Audit system (auditd) is not installed or not in PATH"
  echo "Some monitoring features may not work correctly"
fi

# Create a systemd service file for the application
if [ -d "/etc/systemd/system" ]; then
  echo "📄 Creating systemd service file..."
  
  # Check if service is masked and unmask it if needed
  if systemctl is-enabled agentless.service 2>&1 | grep -q "masked"; then
    echo "🔄 Unmasking existing service..."
    sudo systemctl unmask agentless.service
  fi
  
  # Remove old service if it exists
  if [ -f "/etc/systemd/system/agentless.service" ]; then
    echo "🔄 Removing existing service file..."
    sudo rm -f "/etc/systemd/system/agentless.service"
  fi
  
  # Create new service file
  sudo bash -c "cat > /etc/systemd/system/agentless.service << EOF
[Unit]
Description=AgentLess Web Application
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/agentless
Restart=on-failure
RestartSec=5
StandardOutput=journal+console
StandardError=journal+console
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=GOPATH=$GOPATH

[Install]
WantedBy=multi-user.target
EOF"

  echo "🔄 Reloading systemd..."
  sudo systemctl daemon-reload
  
  echo "✅ Systemd service created"
  echo "To start the service: sudo systemctl start agentless"
  echo "To enable on boot: sudo systemctl enable agentless"
fi

echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "  1. Update the .env file with secure credentials"
echo "  2. Start the application directly: ./agentless"
echo "  3. Or use systemd: sudo systemctl start agentless"
echo "  4. Access the web interface at: http://localhost:8080"
echo ""
echo "🚀 Would you like to start the application now? (y/n)"
read -r start_now

if [[ "$start_now" =~ ^[Yy]$ ]]; then
  # Make sure logs directory exists
  mkdir -p "$LOG_DIR"
  
  # Check if the application was built successfully
  if [ -f "$APP_DIR/agentless" ]; then
    echo "Starting application directly..."
    # Run in background
    nohup "$APP_DIR/agentless" > "$LOG_DIR/app.log" 2>&1 &
    APP_PID=$!
    
    # Check if application started successfully
    sleep 2
    if ps -p $APP_PID > /dev/null; then
      echo "✅ Application started! Access at http://localhost:8080"
      echo "  - Logs are available at: $LOG_DIR/app.log"
      echo "  - Process ID: $APP_PID"
      echo "  - To stop: kill $APP_PID or pkill -f agentless"
    else
      echo "❌ Application failed to start. Check logs at: $LOG_DIR/app.log"
    fi
  else
    echo "❌ Application binary not found. Build may have failed."
  fi
fi
echo ""
echo "For monitoring setup:"
echo "  - Add devices through the web interface"
echo "  - Use the enlist.sh script to configure devices"
echo "  - Check logs in the data directory"
echo ""
