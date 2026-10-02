# High-Availability Hardening & Automated Endpoint Failover

## Overview

The High-Availability Hardening system provides automated, multi-layered failover between administrator-configured Foreign carrier endpoints. 

### Why Endpoint Failover Exists & What It Protects Against
In multi-carrier tunneling architectures between Iran and Foreign data centers, upstream transit providers (such as national infrastructure providers, transit exchanges, or provider DDoS mitigation scrubbers) occasionally experience localized packet loss, routing blackholes, or protocol drops (e.g. dropping ICMP encapsulated packets on a specific IP tuple while SSH/BGP remains reachable).

When an upstream impairment isolates the primary Foreign carrier IP, the endpoint failover system automatically migrates the underlying `udp2raw` ICMP carriers to an explicitly configured secondary Foreign IP.

> [!NOTE]
> This system is designed strictly for **operational resilience and failure recovery**. It does not perform traffic obfuscation, DPI evasion, or protocol impersonation.

---

## Zero Client-Side Configuration Changes
The user's client configuration connects exclusively to the Iran gateway's public application port (`Iran:9094`). Flow balancing and carrier migration take place entirely on the server side:

```
[Unchanged Shadowsocks Client]
             │
             ▼
   [Iran Gateway :9094]
             │ (conntrack flow balancing)
   ┌─────────┼─────────┐
   ▼         ▼         ▼
[wg9094]  [wg9095]  [wg9096]
   │         │         │
   └─────────┼─────────┘
             │  (staged failover)
             ▼
[Active Foreign IP (Primary or Secondary)]
             │
             ▼
      [Germany Xray] ───► [Internet]
```

---

## Layered Health Model

Health evaluation uses a 5-layer hierarchy to differentiate local failures from remote network failures:

1. **`HOST_REACHABLE`**: Probes host reachability (TCP port 22 / SYN).
2. **`ICMP_CARRIER_REACHABLE`**: Tests whether raw ICMP carrier packets can reach the target Foreign IP.
3. **`UDP2RAW_CARRIER_HEALTHY`**: Verifies that local `udp2raw` carrier daemons are active and responding.
4. **`WIREGUARD_HANDSHAKE_HEALTHY`**: Inspects passive WireGuard signals (latest handshake age < 100s, RX/TX counter progression).
5. **`END_TO_END_TUNNEL_HEALTHY`**: Confirms round-trip ping through the tunnel to internal gateways (`10.77.94.2`, `10.77.95.2`, `10.77.96.2`).

---

## Conservative Thresholds & Failure Classification

To prevent false alarms caused by transient network spikes, failover requires sustained failure:

| Failure State | Threshold | Action Taken |
| :--- | :--- | :--- |
| **Local Service Crash** | 1 check | Auto-restart local service (`udp2raw` / `wg-quick`). No endpoint failover. |
| **Routing / Forwarding Issue** | 1 check | Log warning. No endpoint failover. |
| **Firewall Conflict (:9094)** | 1 check | Flag degraded status and warn administrator. |
| **Single Carrier Degraded** | 3 checks | Local carrier restart. Healthy carriers remain active. |
| **Remote Endpoint Failure** | 3 consecutive failed checks (45s) | Validate candidate endpoint → Execute staged failover. |
| **All Endpoints Failed** | Sustained failure across all candidates | Mark `NO_HEALTHY_ENDPOINT`, enter bounded backoff. No endless loops. |

---

## Staged Failover & Flow Safety

When an endpoint migration occurs:
1. **Target Pre-check**: Candidate endpoint is probed to ensure ICMP carrier packets can be received.
2. **Sequential Carrier Migration**: Carriers are migrated one by one (`wg9094` → `wg9095` → `wg9096`).
3. **Handshake Verification**: WireGuard verifies the handshake before proceeding to the next carrier.
4. **Existing TCP/UDP Flows**: Connection tracking (`conntrack`) maintains per-connection affinity. Existing long-lived TCP connections whose underlying carrier moves may retransmit and re-establish gracefully, while ongoing traffic on other carriers remains uninterrupted.

---

## Failback Hysteresis & Cooldown

* **`AUTO_FAILBACK`** (Default: `no`): Prevents flapping back to an unstable primary endpoint.
* **Hysteresis**: When failback is enabled, the primary endpoint must demonstrate continuous health across `RECOVERY_THRESHOLD` (5 consecutive checks) before becoming eligible.
* **`FAILOVER_COOLDOWN`** (Default: `300s`): Imposes a 5-minute cooldown period following any transition to prevent flapping.

---

## State Persistence

Runtime state is persisted across reboots in `/var/lib/iran-de-tunnel/state.json`:
* Active endpoint selection survives server reboots.
* If the server reboots while operating on the secondary endpoint, it boots directly onto the secondary endpoint without reverting to a broken primary.

---

## Management CLI (`tunnelctl`)

### Status Inspection
```bash
tunnelctl status
```

### Candidate Endpoint Inspection
```bash
tunnelctl endpoint list
tunnelctl endpoint check
```

### Manual Endpoint Switch (Administrator Override)
```bash
tunnelctl endpoint switch secondary
# or
tunnelctl endpoint switch 198.51.100.2
```
*Manual switches set `manual_override: true` to prevent automated background transitions.*

### Automation Control
```bash
# Enable automated failover
tunnelctl failover enable

# Disable automated failover (locks to current endpoint)
tunnelctl failover disable

# Toggle automatic failback
tunnelctl failover auto-failback on
```

### Inspecting Transition Logs
Transition logs and failover decisions are recorded in systemd journal:
```bash
journalctl -u tunnel-failover.service -n 100 -f
# or using tunnelctl
tunnelctl logs
```
Each state transition, candidate probe result, and carrier restart is logged with UTC timestamps and failure reasons.

### Behavior When All Endpoints Fail
If all configured Foreign endpoints fail health probes:
1. The system transitions to the `NO_HEALTHY_ENDPOINT` state.
2. It logs a high-severity alert.
3. It does **not** engage in rapid restart thrashing or infinite flapping.
4. It enters bounded exponential backoff (probing every 30s) until at least one administrator-configured endpoint recovers.

### Firewall Conflict Detection
```bash
tunnelctl firewall check
```
Verifies that no unauthorized `iptables` rule or `nftables` table intercepts the public application port (`:9094`).

---

## Configuration Reference

### Standalone Engine (`/etc/iran-de-tunnel/failover.conf`)
```ini
PRIMARY_FOREIGN_ENDPOINT="198.51.100.1"
SECONDARY_FOREIGN_ENDPOINT="198.51.100.2"
FOREIGN_ENDPOINTS="198.51.100.1 198.51.100.2"

AUTO_FAILOVER="yes"
AUTO_FAILBACK="no"

FAILURE_THRESHOLD="3"
RECOVERY_THRESHOLD="5"
FAILOVER_COOLDOWN="300"
CHECK_INTERVAL="15"
HANDSHAKE_STALE_SEC="100"
APP_PORT="9094"
```

### Release 2 Environment (`config.env`)
```env
PRIMARY_FOREIGN_ENDPOINT=198.51.100.1
SECONDARY_FOREIGN_ENDPOINT=198.51.100.2
FOREIGN_ENDPOINTS=198.51.100.1 198.51.100.2
AUTO_FAILOVER=yes
AUTO_FAILBACK=no
FAILURE_THRESHOLD=3
RECOVERY_THRESHOLD=5
FAILOVER_COOLDOWN=300
```
