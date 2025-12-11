#!/bin/bash
# AegisAI Linux Agent Uninstallation Script

set -e

echo "Uninstalling AegisAI Linux Agent..."

# Stop and disable the service
sudo systemctl stop aegisai-agent || true
sudo systemctl disable aegisai-agent || true

# Remove systemd service
sudo rm -f /etc/systemd/system/aegisai-agent.service
sudo systemctl daemon-reload

# Remove the agent binary
sudo rm -f /usr/local/bin/aegisai-agent

echo "AegisAI Linux Agent uninstalled successfully!"
