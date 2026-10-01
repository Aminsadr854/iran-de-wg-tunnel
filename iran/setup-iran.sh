#!/bin/bash
# Multi-Carrier ICMP Tunnel Automated Installer (Iran Gateway)
# Deploys 3 parallel WireGuard-over-udp2raw ICMP carriers with connection-level flow balancing.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Iran Multi-Carrier Tunnel Setup ==="

# 1. Check prerequisites
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

command -v iptables >/dev/null || apt-get install -y iptables
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

# 4. Install relay script and systemd unit
echo "Installing relay script..."
install -m 0755 "$DIR/iran-9094-relay" /usr/local/sbin/iran-9094-relay
install -m 0755 "$DIR/icmp9094-relay" /usr/local/sbin/icmp9094-relay
install -m 0644 "$DIR/iran-9094-relay.service" /etc/systemd/system/iran-9094-relay.service
install -m 0644 "$DIR/icmp9094-relay.service" /etc/systemd/system/icmp9094-relay.service

# 5. Install health check
echo "Installing health monitor..."
install -m 0755 "$DIR/icmp9094-healthcheck" /usr/local/sbin/icmp9094-healthcheck
install -m 0644 "$DIR/icmp9094-healthcheck.service" /etc/systemd/system/icmp9094-healthcheck.service
install -m 0644 "$DIR/icmp9094-healthcheck.timer" /etc/systemd/system/icmp9094-healthcheck.timer

# 6. Configure CPU Affinity safely based on available cores
NUM_CPUS="$(nproc)"
echo "Detected $NUM_CPUS CPU cores."

CARRIERS=(wg9094 wg9095 wg9096)
mkdir -p /etc/udp2raw /etc/wireguard

for i in "${!CARRIERS[@]}"; do
  dev="${CARRIERS[$i]}"
  cpu=$((i % NUM_CPUS))

  echo "Configuring carrier $dev (assigned CPU core $cpu)..."

  # Install systemd service with dynamic CPUAffinity
  cat > "/etc/systemd/system/udp2raw-$dev.service" <<EOF
[Unit]
Description=udp2raw ICMP carrier for $dev
Wants=network-online.target
After=network-online.target

[Service]
CPUAffinity=$cpu
Nice=-10
Type=simple
ExecStart=/usr/local/sbin/udp2raw-wg9094 --conf-file /etc/udp2raw/$dev.conf
Restart=always
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  # Install WireGuard dependency drop-in override
  mkdir -p "/etc/systemd/system/wg-quick@$dev.service.d"
  cat > "/etc/systemd/system/wg-quick@$dev.service.d/override.conf" <<EOF
[Unit]
Requires=udp2raw-$dev.service
After=udp2raw-$dev.service
EOF
done

systemctl daemon-reload

echo "=== Systemd and scripts installed successfully ==="
echo "Next step: Ensure /etc/udp2raw/wg909X.conf and /etc/wireguard/wg909X.conf are populated with keys/secrets."
echo "Then enable services via:"
echo "  systemctl enable --now udp2raw-wg9094 udp2raw-wg9095 udp2raw-wg9096"
echo "  systemctl enable --now wg-quick@wg9094 wg-quick@wg9095 wg-quick@wg9096"
echo "  systemctl enable --now iran-9094-relay.service icmp9094-healthcheck.timer"
