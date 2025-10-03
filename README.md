# Agent< IDS

A lightweight and agentless HIDS which supports Linux (Debian/RHEL) monitoring through auditd and Windows monitoring through Sysmon. Logs are gathered through auditd and Sysmon rules, and then extracted to the webserver using SSH, where they can be displayed.

## Features

- **Agentless Monitoring**: No agent installation required on target devices. Only things moved to endpoints are temporary setup scripts which install required dependencies. Because of this, the client doesn't connect to the server to send logs, instead, the server connects to the client and gathers them itself.
- **Security Event Classification**: Automatically classifies events by severity. These severities can be modified. By default, LOW usually means regular system tasks or regular events, MEDIUM can signal changes made to relatively important directories/configurations, and HIGH is mostly reserved for suspicious command execution.

## Prerequisites

- Linux server/VM (Ubuntu Server is recommended. Debian+RHEL is supported, but untested)
- Go 1.16+ (for building the web application)
- SQLite3 with SQLCipher extension
- SSH server on target devices
- Systemd (for service management)
- Root or sudo access through SSH on the monitoring server

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/nitrogency/agentLess.git
cd agentLess
```   

### 2. Run the setup script

```bash
chmod +x setup.sh
./setup.sh
```

You can find a more-detailed write-up of how the app works + some best-practices in the `docs` section.