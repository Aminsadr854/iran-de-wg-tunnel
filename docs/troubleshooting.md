# Multi-Carrier Tunnel Troubleshooting Guide

## 1. One Carrier is Down or Failing Pings

Check which specific carrier is degraded:
```bash
# Check WireGuard handshakes and endpoints
wg show

# Test connectivity on each interface
ping -I wg9094 -c 3 10.77.94.2
ping -I wg9095 -c 3 10.77.95.2
ping -I wg9096 -c 3 10.77.96.2
```

If a carrier fails:
1. Inspect the carrier's `udp2raw` daemon:
   ```bash
   systemctl status udp2raw-wg909X.service
   journalctl -u udp2raw-wg909X.service -n 50 --no-pager
   ```
2. Verify matching pre-shared keys and secrets in `/etc/udp2raw/wg909X.conf`.
3. Restart only the failing carrier:
   ```bash
   systemctl restart udp2raw-wg909X.service
   sleep 2
   systemctl restart wg-quick@wg909X.service
   ```

---

## 2. Asymmetric Traffic Distribution

Inspect the connection distribution counters:
```bash
iptables -t nat -vnL WG9094_DNAT
```
- Each carrier rule should have roughly equal packet/byte counts over time.
- If one carrier shows zero packets, verify that the `nth` rules are ordered correctly:
  - First rule: `--every 3 --packet 0`
  - Second rule: `--every 2 --packet 0`
  - Third rule: Default (no statistic match)
- Verify `conntrack` is functioning:
  ```bash
  cat /proc/sys/net/netfilter/nf_conntrack_count
  conntrack -L -p tcp --dport 9094
  ```

---

## 3. High CPU Usage or Latency Bloat

If latency spikes under load:
1. Check context switching frequency on Iran:
   ```bash
   vmstat 1 5
   ```
   - Normal operation: `cs` < 15,000 / sec.
   - If `cs` > 50,000 / sec and CPU idle is 0%, ensure only 3 carriers are active. Do not exceed 3 carriers on a 3-vCPU machine.
2. Verify CPU Affinity:
   ```bash
   taskset -c -p $(pgrep -f "udp2raw-wg9094.*wg9094.conf")
   taskset -c -p $(pgrep -f "udp2raw-wg9094.*wg9095.conf")
   taskset -c -p $(pgrep -f "udp2raw-wg9094.*wg9096.conf")
   ```
   Each process should show a distinct CPU mask (0, 1, and 2).

---

## 4. Packet Loss or Stalling

1. **Verify MTU**:
   Ensure all WireGuard interfaces on both hosts have `MTU = 900`:
   ```bash
   ip link show wg9094
   ip link show wg9095
   ip link show wg9096
   ```
2. **Verify MSS Clamping**:
   Confirm the PMTU clamping rule is active in the `FORWARD` mangle chain:
   ```bash
   iptables -t mangle -vnL FORWARD
   ```
   Rule `-j TCPMSS --clamp-mss-to-pmtu` must show counter increments.
3. **Dedicated Source Ports**:
   Ensure each carrier on Iran specifies `--source-port` (42094, 42095, 42096) and a unique `-k <secret>` in its config file to prevent `PF_PACKET` raw socket interception collisions.

---

## 5. Automated Health Check & Healing

The system includes an automated watchdog (`icmp9094-healthcheck.timer`):
- Runs every 60 seconds.
- Probes all 3 carriers independently.
- If any carrier registers 3 consecutive failed pings, the watchdog restarts that carrier's `udp2raw` and `wg-quick` services automatically while leaving the remaining two carriers untouched.
- View watchdog logs:
  ```bash
  journalctl -t icmp9094-health -n 50 --no-pager
  ```
