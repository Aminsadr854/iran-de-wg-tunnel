# Setup Guide

Reproduces the Iran ↔ Germany WireGuard-over-udp2raw tunnel with port 9093
forwarding.

## Prerequisites

- Two servers, referred to below as `IRAN` and `DE`.
- Root SSH access to both.
- Ubuntu/Debian (tested on Ubuntu 22.04). Adjust package manager commands for
  other distros.

## 1. Install WireGuard on both servers

```bash
apt-get update -qq && apt-get install -y wireguard
```

## 2. Generate keys

On each server:

```bash
umask 077
wg genkey | tee privatekey | wg pubkey > publickey
```

Note the private/public key of each side — you'll need DE's public key on
IRAN's config and vice versa.

## 3. Download and install udp2raw on both servers

```bash
cd /tmp
wget -q https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz
tar -xzf udp2raw_binaries.tar.gz
mv udp2raw_amd64 /usr/local/bin/udp2raw
chmod +x /usr/local/bin/udp2raw
rm -f udp2raw_* udp2raw_binaries.tar.gz version.txt
```

Adjust the binary name for your architecture if not `amd64`.

## 4. Generate a shared secret for udp2raw

```bash
openssl rand -hex 24
```

Use the same value in both `udp2raw-client.service` (Iran) and
`udp2raw-server.service` (Germany), replacing `<SHARED_SECRET>`.

## 5. Deploy WireGuard configs

- Copy `germany/wg0.conf.template` to `/etc/wireguard/wg0.conf` on DE,
  filling in DE's private key and Iran's public key.
- Copy `iran/wg0.conf.template` to `/etc/wireguard/wg0.conf` on IRAN, filling
  in Iran's private key and Germany's public key.
- `chmod 600 /etc/wireguard/wg0.conf` on both.

Note: Iran's `Endpoint` points to `127.0.0.1:4097` — WireGuard on Iran talks
to the local udp2raw client, not directly to Germany. Germany's `Endpoint`
points to Iran's real public IP:443, but since Iran initiates the connection
through udp2raw, this value mostly matters for the initial expected peer
address bookkeeping.

## 6. Deploy udp2raw systemd services

- Copy `germany/udp2raw-server.service` to `/etc/systemd/system/udp2raw.service` on DE.
- Copy `iran/udp2raw-client.service` to `/etc/systemd/system/udp2raw.service` on IRAN.
- Fill in `<GERMANY_PUBLIC_IP>` and `<SHARED_SECRET>` in the Iran service file.
- Fill in `<SHARED_SECRET>` in the Germany service file.

Start order matters — bring up the server (Germany) side first:

```bash
# On Germany:
systemctl daemon-reload
systemctl enable --now udp2raw

# On Iran:
systemctl daemon-reload
systemctl enable --now udp2raw
```

## 7. Start WireGuard

```bash
# On Germany:
systemctl enable --now wg-quick@wg0

# On Iran:
systemctl enable --now wg-quick@wg0
```

## 8. Verify the tunnel

On Iran:

```bash
wg show
ping -c 5 10.20.20.2
```

You should see a recent handshake and low packet loss. If you see 100% loss,
restart both `udp2raw` services (server first, then client) followed by both
`wg-quick@wg0` services — the underlying faketcp connection state can get out
of sync after config changes.

## 9. Enable forwarding and NAT rules (Iran only)

```bash
bash iran/sysctl-forwarding.sh
bash iran/iptables-rules.sh
apt-get install -y iptables-persistent
netfilter-persistent save
```

## 10. Test end-to-end

From any external machine:

```bash
# TCP
timeout 5 bash -c '</dev/tcp/<IRAN_PUBLIC_IP>/9093' && echo OK

# UDP
echo test | nc -u -w2 <IRAN_PUBLIC_IP> 9093
```

Check `iptables -t nat -L PREROUTING -n -v` on Iran — the packet counters on
the DNAT rules should increment.
