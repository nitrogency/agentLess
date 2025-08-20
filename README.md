# AgentLess IDS

A lightweight, agentless intrusion detection system that monitors remote Linux systems using SSH and Linux auditd. The system provides a web interface for managing monitored devices and viewing security events.

## Features

- **Agentless Monitoring**: No software installation required on target devices
- **Real-time Audit Log Collection**: Collects and analyzes Linux audit logs
- **Security Event Classification**: Automatically classifies events by severity (low, medium, high)

## Prerequisites

- Linux server/VM (Ubuntu/Debian recommended. RHEL support is untested.)
- Go 1.16+ (for building the web application)
- SQLite3 with SQLCipher extension
- SSH server on target devices
- Systemd (for service management)
- Root or sudo access on the monitoring server

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/nitrogency/agentLess.git
cd agentLess
```   

### 2. Run the setup script

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

## Adding custom rules
If you wish to add custom audit rules, all you have to do is to edit the enlist.sh script, which is responsible for rule creation on the target system.
You can find a guide for audit rules [here](https://www.redhat.com/en/blog/configure-linux-auditing-auditd).


## Hardening
Make sure to at least somewhat harden your host VM.

```bash
# Enable automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure firewall
sudo ufw allow ssh
sudo ufw allow 8080/tcp  # Web interface port
sudo ufw enable

# Disable root login over SSH
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

