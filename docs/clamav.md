# ClamAV integration

Endpoint config template: `/scripts/cron/clamav-scan.template`

Server config template: `/scripts/systemd/agentless-clamav-scan.service`

Server scan timer template: `/scripts/systemd/agentless-clamav-scan.timer`


ClamAV is installed on both the server and Linux endpoints. **Windows devices are unsupported.**

It was chosen due to it's easy integration (you can make it write logs to files, which can then be gathered through SSH). Plus, it's free and lightweight.

Virus definitions are automatically updated every hour by ClamAV's `freshclam` service.

The server uses a systemd timer to periodically scan specified directories (both the directories and time period can be changed in `scripts/systemd/agentless-clamav-scan.timer` and `scripts/systemd/agentless-clamav-scan.service`). Infected files are automatically moved to quarantine in `/var/log/clamav/quarantine`. Only infected file detections are logged to `/var/log/clamav/clamav.log`. Regular scan information is **NOT** logged to avoid flooding the logs.

ClamAV on the server is installed during the `harden.sh` script.

Endpoints use a cronjob instead of a systemd timer for better compatibility between distros. The cronjob runs daily, and scans the same directories as the server. Infected file detections are logged to `/var/log/clamav/clamav.log`. Found files are **NOT** quarantined on endpoints. This can be changed.

The app uses a default ClamAV cron template that's in `scripts/cron/clamav-scan.template`. **The defaults for this template can be changed in `scripts/lib/config.sh`.** Re-run the `enroll-device.sh` script to apply the changes to the endpoint.

ClamAV on endpoints is installed during the `enroll-device.sh` script.