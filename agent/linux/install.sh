#!/bin/bash
# AegisAI Linux Agent Installation Script

set -e

echo "Installing AegisAI Linux Agent..."

# Build the agent
mkdir -p build
cd build
cmake ..
make

# Install the agent
sudo make install

# Install systemd service
sudo cp aegisai-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegisai-agent

echo "AegisAI Linux Agent installed successfully!"
echo "To start the agent, run: sudo systemctl start aegisai-agent"
