#!/bin/bash
# Run on the Iran server. Forwards TCP+UDP port 9093 through the WireGuard
# tunnel to the Germany server (10.20.20.2), which must already be reachable
# via wg0 before these rules take effect.
set -e

EXT_IFACE="eth0"          # external/public interface on the Iran box
TUNNEL_PEER="10.20.20.2"  # Germany's tunnel IP
PORT=9093

# DNAT: incoming traffic on $EXT_IFACE:$PORT -> forwarded to Germany over the tunnel
iptables -t nat -A PREROUTING -i "$EXT_IFACE" -p tcp --dport "$PORT" -j DNAT --to-destination "$TUNNEL_PEER:$PORT"
iptables -t nat -A PREROUTING -i "$EXT_IFACE" -p udp --dport "$PORT" -j DNAT --to-destination "$TUNNEL_PEER:$PORT"

# MASQUERADE so return traffic routes back correctly through the tunnel
iptables -t nat -A POSTROUTING -o wg0 -p tcp --dport "$PORT" -d "$TUNNEL_PEER" -j MASQUERADE
iptables -t nat -A POSTROUTING -o wg0 -p udp --dport "$PORT" -d "$TUNNEL_PEER" -j MASQUERADE

# Explicitly allow forwarding for this traffic
iptables -A FORWARD -p tcp --dport "$PORT" -d "$TUNNEL_PEER" -j ACCEPT
iptables -A FORWARD -p udp --dport "$PORT" -d "$TUNNEL_PEER" -j ACCEPT
iptables -A FORWARD -p tcp --sport "$PORT" -s "$TUNNEL_PEER" -j ACCEPT
iptables -A FORWARD -p udp --sport "$PORT" -s "$TUNNEL_PEER" -j ACCEPT

echo "iptables rules applied for port $PORT -> $TUNNEL_PEER"

# Persist across reboots (Debian/Ubuntu):
#   apt-get install -y iptables-persistent
#   netfilter-persistent save
