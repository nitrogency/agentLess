# Security and Hardening
It is **heavily** recommended that you use a separate VM/host/LXC container for just running the app, and nothing else. Since the app is relatively lightweight, this generally shouldn't be a problem.

**This app is not designed to be exposed to the web.** Make sure it is only accessible from your local network.
## System Hardening

An optional hardening script called `scripts/harden.sh` is provided to apply some basic security hardening measures to your monitoring server. This includes:

- Configuring automatic system updates.
- Configuring sshd (disables root login, sets max login attempts, disables X11 forwarding)
- Installing and configuring clamav.
- Installing and configuring fail2ban. Fail2ban logs both SSH login attempts, and also login attempts in the page's login form itself. Configuration can be modified in the `harden.sh` script itself, by default it bans SSH logins for an hour after 3 attempts and web logins for 30 minutes after 5 attempts.
- Installing and configuring ufw. By default all incoming traffic is blocked except for the set SSH port (default 22) and the web service port (default 8443). **By default, all outgoing traffic is allowed. You should change this according to your environment.**
- Installing and configuring auditd. By default, it uses the default 64-bit ruleset. Logs are **not** sent to the dashboard to better separate device logs from server logs. You can view logs using the `ausearch` tool, or by reading `audit.log`.
- Generic unnecessary service disabling. This list can be expanded and changed in the script. 

## Endpoint security

For ensuring better Linux endpoint security, clamav is also automatically installed and configured to periodically update and run daily scans via cron. Logs are also sent to the dashboard from `clamav.log`. If the auditd service is the "behavior-based" detection part of the app, this would be the "signature-based" portion.

Make sure to allow only appropriate IP/port access on your endpoints.