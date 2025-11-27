# Requirements and Prerequisites
- For the server, a minimum of 2GB RAM and 2VCPUs is recommended. Storage requirements depends on the amount you plan to log. A minimum of 20GB is recommended. Requirements heavily depend on how many devices you plan to monitor.
- Linux server/VM (Ubuntu Server is recommended. Debian+RHEL is supported, but untested)
- SSH server on target devices (installed by default on most Linux distributions, installed automatically by the enrollment script on Windows)
- Systemd (for service management)
- Root or sudo access through SSH on the monitoring server
- Sudo user access through SSH to your Linux endpoints

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

After setup, the web interface should be accessible at https://localhost:8443.

After the script is done, the cloned repository is wiped and the application is installed to `/opt/agentless`. **Be sure to `cd` out of the removed directory once install is complete.** If you run any endpoint enrollment scripts while in the deleted directory, they will **FAIL**.

# After installation
At the end of the `setup.sh` script, the `agentless` service is created. This service runs and handles the web application.

To view the status of the service, type:
```bash
sudo systemctl status agentless
```
If you wish to `restart`, `stop` or `disable` the service, replace the `status` word accordingly.

The status of other services the application uses can be viewed and handled similarly. Just replace the service name.

## Logging

To view the web service log, type:
```bash
sudo journalctl -u agentless
```

Other app related logs (login attempts, script results) are saved in `/var/log/agentless/`. You need sudo permissions to view these logs.

## Certificates

By default, the app does not support HTTP. During setup, a self-signed certificate is generated in the `certs/` directory. To re-generate them, remove them and run the `setup.sh` script again.

## Installed app structure

```
/opt/agentless/          # Main installation directory
├── agentless            # Main application binary
├── bin/                 # Monitoring binaries
│   ├── monitor          # Linux monitoring binary
│   └── monitor-windows  # Windows monitoring binary
├── certs/               # SSL/TLS certificates
├── cmd/                 # Go command programs
│   └── exporter/        # Log export utility (optional)
├── config/              # Configuration package
├── data/                # SQLite database
│   └── site.db          # Encrypted database file
├── db/                  # Database access layer
├── handlers/            # HTTP request handlers
├── middleware/          # HTTP middleware
├── models/              # Data structures
├── rulesets/            # Audit rule templates
│   ├── x32/             # 32-bit rulesets
│   └── x64/             # 64-bit rulesets
├── scripts/             # Operational scripts
│   ├── systemd/         # Systemd unit templates
│   ├── lib/             # Shared libraries for scripts
│   ├── linux/           # Linux monitoring and enrollment scripts
│   ├── windows/         # Windows monitoring and enrollment scripts
│   ├── cleanup/         # Log retention scripts
│   ├── rotate/          # Secret rotation scripts
│   ├── export/          # Log export setup scripts
│   ├── cron/            # Cron templates for endpoints
│   ├── harden.sh        # Security hardening script
│   ├── setup-monitoring.sh   # Monitoring service setup
│   └── start-monitoring.sh   # Monitoring launcher
├── server/              # HTTP server package
├── static/              # Web assets
│   ├── css/             # Stylesheets
│   └── js/              # JavaScript
├── templates/           # HTML templates
├── utils/               # Utility functions
├── .env                 # Non-secret configuration
├── go.mod               # Go dependencies
├── go.sum               # Dependency checksums
└── main.go              # Application entry point
```

## Troubleshooting

If you run into any issues regarding the database, make sure you're using sqlcipher when querying manually - queries using sqlite3 will fail as it won't recognize the file as a database. 

Most of the scripts support logging. Output can be found in in `/var/log/agentless/`.
