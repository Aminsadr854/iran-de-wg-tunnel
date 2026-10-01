#!/bin/bash
# Multi-Carrier Tunnel Full Uninstaller (Foreign/Germany Host)
# Removes only project-owned files and services.

set -euo pipefail

echo "Executing rollback..."
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$DIR/icmp9094-rollback" ]; then
  bash "$DIR/icmp9094-rollback"
fi

echo "Removing systemd units..."
for dev in wg9094 wg9095 wg9096; do
  rm -f "/etc/systemd/system/udp2raw-$dev.service"
  rm -rf "/etc/systemd/system/wg-quick@$dev.service.d"
done

echo "Removing configuration files..."
for dev in wg9094 wg9095 wg9096; do
  rm -f "/etc/wireguard/$dev.conf"
  rm -f "/etc/udp2raw/$dev.conf"
done
rm -f /etc/sysctl.d/99-tunnel-optimize.conf

systemctl daemon-reload
sysctl --system >/dev/null 2>&1 || true

echo "Foreign tunnel uninstalled successfully."
