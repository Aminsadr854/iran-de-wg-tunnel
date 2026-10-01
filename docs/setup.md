# Reproduce the 3-Carrier Production Tunnel

This guide provides step-by-step instructions to reproduce the proven 3-carrier WireGuard-over-udp2raw ICMP tunnel on a clean pair of Iran and Germany servers, or upgrade an existing single-carrier deployment.

---

## Carrier Network Mapping

| Parameter | Carrier 1 (`wg9094`) | Carrier 2 (`wg9095`) | Carrier 3 (`wg9096`) |
| :--- | :--- | :--- | :--- |
| **Iran WG IP** | `10.77.94.1/30` | `10.77.95.1/30` | `10.77.96.1/30` |
| **Foreign WG IP** | `10.77.94.2/30` | `10.77.95.2/30` | `10.77.96.2/30` |
| **udp2raw Outer Port (ICMP)** | `42094` | `42095` | `42096` |
| **udp2raw Fixed Source Port** | `42094` | `42095` | `42096` |
| **Iran Local Loopback Endpoint** | `127.0.0.1:51895` | `127.0.0.1:51897` | `127.0.0.1:51891` |
| **Foreign WG Listen Port** | `51894` | `51895` | `51892` |
| **Iran WG Listen Port** | `51896` | `51898` | `51892` |
| **Interface MTU** | `900` | `900` | `900` |
| **Iran CPU Affinity** | Core 0 | Core 1 | Core 2 |

---

## Phase 1: Deploy Foreign / Germany Server

### 1. Run Automated Setup
```bash
git clone https://github.com/Aminsadr854/iran-de-wg-tunnel.git /opt/iran-de-wg-tunnel
cd /opt/iran-de-wg-tunnel/foreign
bash setup-foreign.sh
```

### 2. Generate Keys & Populate Configurations
Generate 3 distinct WireGuard keypairs, 3 shared PSKs, and 3 random udp2raw secrets:
```bash
mkdir -p /etc/wireguard /etc/udp2raw
chmod 700 /etc/wireguard /etc/udp2raw

for dev in wg9094 wg9095 wg9096; do
  wg genkey > "/etc/wireguard/${dev}.private"
  wg pubkey < "/etc/wireguard/${dev}.private" > "/etc/wireguard/${dev}.public"
  wg genpsk > "/etc/wireguard/${dev}.psk"
  openssl rand -hex 16 > "/etc/udp2raw/${dev}.secret"
done
```

Populate `/etc/udp2raw/wg909*.conf` and `/etc/wireguard/wg909*.conf` from the templates in `foreign/`, filling in the generated keys and Iran's public keys.

### 3. Start Foreign Services
```bash
systemctl daemon-reload
systemctl enable --now udp2raw-wg9094 udp2raw-wg9095 udp2raw-wg9096
systemctl enable --now wg-quick@wg9094 wg-quick@wg9095 wg-quick@wg9096
```

---

## Phase 2: Deploy Iran Gateway Server

### 1. Run Automated Setup
```bash
git clone https://github.com/Aminsadr854/iran-de-wg-tunnel.git /opt/iran-de-wg-tunnel
cd /opt/iran-de-wg-tunnel/iran
bash setup-iran.sh
```

### 2. Populate Configurations
Generate Iran's 3 WireGuard keypairs:
```bash
mkdir -p /etc/wireguard /etc/udp2raw
chmod 700 /etc/wireguard /etc/udp2raw

for dev in wg9094 wg9095 wg9096; do
  wg genkey > "/etc/wireguard/${dev}.private"
  wg pubkey < "/etc/wireguard/${dev}.private" > "/etc/wireguard/${dev}.public"
done
```
Copy Foreign's public keys, PSKs, and udp2raw secrets to Iran. Populate `/etc/udp2raw/wg909*.conf` and `/etc/wireguard/wg909*.conf` from `iran/` templates.

### 3. Start Iran Services & Relay
```bash
systemctl daemon-reload
systemctl enable --now udp2raw-wg9094 udp2raw-wg9095 udp2raw-wg9096
systemctl enable --now wg-quick@wg9094 wg-quick@wg9095 wg-quick@wg9096
systemctl enable --now iran-9094-relay.service icmp9094-healthcheck.timer
```

---

## Phase 3: Verification

### 1. Verify WireGuard Handshakes
```bash
# On Iran
wg show
```
All 3 interfaces (`wg9094`, `wg9095`, `wg9096`) must display recent handshakes.

### 2. Verify Carrier Connectivity
```bash
# From Iran
ping -c 3 10.77.94.2
ping -c 3 10.77.95.2
ping -c 3 10.77.96.2
```
All 3 pings must return 0% packet loss.

### 3. Verify Flow Balancing
```bash
iptables -t nat -vnL WG9094_DNAT
```
Counters for each of the 3 rules should increment symmetrically as new client connections arrive.

---

## Upgrade Path from Single-Carrier

If upgrading from the old single-carrier (`wg9094`) deployment:
1. Do **not** delete the existing `wg9094` configuration.
2. Deploy `wg9095` and `wg9096` configurations alongside `wg9094`.
3. Update `udp2raw-wg9094.conf` to use `--cipher-mode xor --auth-mode simple` on both ends.
4. Replace `icmp9094-relay` with `iran-9094-relay` and reload.
5. The public endpoint `:9094` remains active throughout the migration with minimal connection churn.

---

## Rollback & Uninstallation

### Rollback
To pause or stop the tunnel without deleting configurations:
```bash
# On Iran
/opt/iran-de-wg-tunnel/iran/icmp9094-rollback

# On Foreign
/opt/iran-de-wg-tunnel/foreign/icmp9094-rollback
```

### Full Uninstall
To completely remove all project-owned systemd units, relay scripts, firewall chains, and sysctl settings:
```bash
# On Iran
bash /opt/iran-de-wg-tunnel/iran/uninstall.sh

# On Foreign
bash /opt/iran-de-wg-tunnel/foreign/uninstall.sh
```
