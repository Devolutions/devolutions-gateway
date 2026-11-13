#!/bin/sh
# Removes the Devolutions Agent and its data from this Linux machine.
# Usage: curl -fsSL https://<host>/uninstall-agent.sh | sudo sh

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script as root (sudo)." >&2
    exit 1
fi

if command -v dpkg >/dev/null 2>&1 && dpkg -s devolutions-agent >/dev/null 2>&1; then
    echo "Removing the devolutions-agent package..."
    apt-get purge -y devolutions-agent >/dev/null
elif command -v rpm >/dev/null 2>&1 && rpm -q devolutions-agent >/dev/null 2>&1; then
    echo "Removing the devolutions-agent package..."
    rpm -e devolutions-agent
fi

echo "Removing the service..."
systemctl disable --now devolutions-agent >/dev/null 2>&1 || true
rm -f /etc/systemd/system/devolutions-agent.service /usr/bin/devolutions-agent
systemctl daemon-reload

echo "Removing the agent data..."
rm -rf /etc/devolutions-agent /var/lib/devolutions-agent

echo "The Devolutions Agent is removed."
