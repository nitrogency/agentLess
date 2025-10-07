# Requirements and Prerequisites
- For the server, a minimum of 2GB RAM and 2VCPUs is recommended.
- Linux server/VM (Ubuntu Server is recommended. Debian+RHEL is supported, but untested)
- Go 1.16+ (for building the web application)
- SQLite3 with SQLCipher extension
- SSH server on target devices
- Systemd (for service management)
- Git installed on monitoring server
- Root or sudo access through SSH on the monitoring server

## Installation

### 1. Clone the Repository

Once SSHed into your monitoring server, you can clone the repo and `cd` into it:
```bash
git clone https://github.com/nitrogency/agentLess.git
cd agentLess
```   

### 2. Run the setup script

This sets up the necessary requirements and builds the application.
```bash
chmod +x setup.sh
./setup.sh
```

## After installation
At the end of the `setup.sh` script, a systemd service is created. This allows for easier debugging and log management. To view the status of the web app, simply type:
```bash
sudo systemctl status agentless
```
If you wish to `restart`, `stop` or `disable` the service, replace the `status` word accordingly.

To view the service log, type:
```bash
journalctl -u agentless
```