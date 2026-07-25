#!/bin/bash
# Run on the Iran server. Enables IP forwarding and persists it in sysctl.conf.
set -e

sysctl -w net.ipv4.ip_forward=1
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p >/dev/null

echo "ip_forward enabled and persisted"
