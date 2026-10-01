#!/bin/bash
# Multi-Carrier ICMP Tunnel Automated Installer (Foreign / Germany Host)
# Sets up 3 parallel WireGuard-over-udp2raw ICMP listeners for traffic delivery.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Foreign Multi-Carrier Tunnel Setup ==="

# 1. Check prerequisites
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

command -v wg >/dev/null || apt-get install -y wireguard-tools

# 2. Install udp2raw binary if missing
if [ ! -x /usr/local/sbin/udp2raw-wg9094 ]; then
  echo "Building udp2raw binary..."
  apt-get update && apt-get install -y build-essential git
  SRC_DIR=/usr/local/src/udp2raw-icmp9094
  if [ ! -d "$SRC_DIR" ]; then
    git clone https://github.com/wangyu-/udp2raw-tunnel.git "$SRC_DIR"
  fi
  (
    cd "$SRC_DIR"
    git checkout 4208db6e27c46f3ccec8b98722af7ec23bc62e73
    make -j"$(nproc)"
    install -o root -g root -m 0755 udp2raw /usr/local/sbin/udp2raw-wg9094
  )
fi

# 3. Apply kernel sysctl performance optimizations
echo "Applying kernel sysctl optimizations..."
install -m 0644 "$DIR/99-tunnel-optimize.conf" /etc/sysctl.d/99-tunnel-optimize.conf
sysctl -p /etc/sysctl.d/99-tunnel-optimize.conf >/dev/null

# 4. Install systemd service files
echo "Installing systemd units and drop-in overrides..."
CARRIERS=(wg9094 wg9095 wg9096)
mkdir -p /etc/udp2raw /etc/wireguard

for dev in "${CARRIERS[@]}"; do
  install -m 0644 "$DIR/udp2raw-$dev.service" "/etc/systemd/system/udp2raw-$dev.service"

  mkdir -p "/etc/systemd/system/wg-quick@$dev.service.d"
  cat > "/etc/systemd/system/wg-quick@$dev.service.d/override.conf" <<EOF
[Unit]
Requires=udp2raw-$dev.service
After=udp2raw-$dev.service
EOF
done

systemctl daemon-reload

echo "=== Foreign systemd and scripts installed successfully ==="
echo "Next step: Ensure /etc/udp2raw/wg909X.conf and /etc/wireguard/wg909X.conf are populated with keys/secrets."
echo "Then enable services via:"
echo "  systemctl enable --now udp2raw-wg9094 udp2raw-wg9095 udp2raw-wg9096"
echo "  systemctl enable --now wg-quick@wg9094 wg-quick@wg9095 wg-quick@wg9096"
