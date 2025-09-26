#!/bin/bash
# install-cleanup-timer.sh [retention_days]
# Installs a systemd oneshot service + timer to purge old audit logs daily.
set -euo pipefail

RETENTION_DAYS="${1:-30}"
REPO_ROOT="/home/nitrogue/Documents/agentLess"
SERVICE_PATH="/etc/systemd/system/agentless-cleanup.service"
TIMER_PATH="/etc/systemd/system/agentless-cleanup.timer"

# Create service
sudo bash -c "cat > '$SERVICE_PATH' <<EOF
[Unit]
Description=AgentLess IDS - Cleanup old audit logs
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$REPO_ROOT
ExecStart=/usr/bin/env bash -lc '$REPO_ROOT/scripts/cleanup-audit-logs.sh $RETENTION_DAYS'
# Allow access to files under /home (tighten if you relocate DB or run as dedicated user)
ProtectHome=false
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF"

# Create timer
sudo bash -c "cat > '$TIMER_PATH' <<EOF
[Unit]
Description=Run AgentLess cleanup daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable --now agentless-cleanup.timer

echo "Installed:"
systemctl list-timers | grep agentless-cleanup || true
