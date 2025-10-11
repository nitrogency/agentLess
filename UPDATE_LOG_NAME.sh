#!/bin/bash
# Quick script to apply the security.log rename

echo "Rebuilding application..."
cd /opt/agentless
go build -o agentless

echo "Restarting service..."
sudo systemctl restart agentless

echo "Checking new log file..."
sudo ls -la /var/log/agentless/security.log

echo ""
echo "Done! Security log renamed to: /var/log/agentless/security.log"
echo "View it with: sudo tail -f /var/log/agentless/security.log"
