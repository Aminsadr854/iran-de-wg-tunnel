# Multi-Carrier WireGuard-over-udp2raw ICMP Tunnel (Port 9094)

High-throughput, censorship-resistant production tunnel bridging **Iran** and **Germany** using **three parallel WireGuard-over-udp2raw ICMP carriers** with deterministic flow-level load balancing.

---

## 1. Verified Architecture & Topology

Incoming client traffic arrives at Iran's public endpoint on `:9094` (TCP/UDP) and is transparently balanced across three independent ICMP carrier tunnels. The client configuration remains completely unchanged and unaware of the multi-carrier underlying topology.

```text
               Existing Unchanged Client Configuration
                      (Shadowsocks 2022 / TCP+UDP)
                                  │
                                  ▼
                       Iran Public Endpoint :9094
                                  │
            iptables PREROUTING Flow Balancing (SYN & UDP)
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
     Carrier 1 (wg9094)   Carrier 2 (wg9095)   Carrier 3 (wg9096)
      10.77.94.1/30        10.77.95.1/30        10.77.96.1/30
     udp2raw ICMP :42094  udp2raw ICMP :42095  udp2raw ICMP :42096
      (CPU Core 0)         (CPU Core 1)         (CPU Core 2)
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  │
                      Underlying Raw ICMP Echo Path
                          (MTU 900 / Internet)
                                  │
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
     Foreign wg9094       Foreign wg9095       Foreign wg9096
      10.77.94.2/30        10.77.95.2/30        10.77.96.2/30
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  │
                                  ▼
                  Foreign Inbound Relay / Xray Server
                                (*:9094)
                                  │
                                  ▼
                         Global Internet (DE)
```

---

## 2. Core Architectural Decisions

### Why Three Parallel Carriers?
Single-carrier user-space tunneling (`udp2raw`) encounters a strict throughput ceiling of ~30–40 Mbps on virtualized Linux systems due to per-core context switching limits (~60,000+ context switches/sec). Distributing traffic across three parallel carrier tunnels parallelizes packet handling across multiple independent processes and CPU cores.

### Why Default Carrier Count is 3 (The Scaling Knee)
Extensive empirical benchmarking on the Iran server (3 vCPUs) demonstrated:
- **3 Carriers**: Optimal sweet spot. Each carrier maps 1:1 to an available vCPU, minimizing involuntary context switching and maintaining ~111 ms loaded latency. Sustained **129.24 Mbps** (60s) and **113.97 Mbps** (5-min).
- **4 Carriers**: Marginally higher volume in one extended benchmark (+5.3%), but context switches spiked to 56,000 cs/s.
- **5 Carriers**: Caused severe CPU exhaustion (0% idle, load > 8 on 3 vCPUs), throughput degradation (-17%), and a 700% explosion in DNS latency (to 928 ms).
Therefore, **3 carriers is the proven production default**.

### Why Flow-Level Balancing (and Not Per-Packet Round-Robin)?
TCP is strictly sensitive to out-of-order packet delivery. Per-packet round-robin causes severe packet reordering, triggering duplicate ACKs, false congestion detection, and TCP window collapse. Flow balancing operates via `iptables -m statistic --mode nth` matching exclusively on TCP `SYN` packets; Linux `conntrack` ensures all subsequent packets belonging to an established TCP connection follow the exact same carrier.

### Why WireGuard Encrypts and udp2raw Uses `xor` / `simple`
- **WireGuard**: Provides true, cryptographically secure end-to-end encryption (ChaCha20-Poly1305) and peer authentication in the Linux kernel.
- **udp2raw**: Solely encapsulates UDP into fake ICMP Echo packets to bypass UDP blocking or severe throttling on international transit links.
- Previous configurations used software AES-128-CBC inside `udp2raw`, which caused severe CPU saturation on VPS hosts lacking AES-NI. Using `--cipher-mode xor --auth-mode simple` in `udp2raw` offloads cryptographic heavy lifting to the kernel WireGuard subsystem.

### Why MTU 900?
Encapsulating WireGuard packets inside udp2raw ICMP packets introduces additional outer headers (IP header + ICMP header + udp2raw header + WireGuard header). On restricted networks, packets exceeding 1000–1200 bytes undergo fragmentation or drop silently. An MTU of **900** bytes completely prevents path fragmentation and eliminates transmission stalls.

### Why TCP MSS Clamping to PMTU?
Path MTU Discovery (PMTUD) is frequently blocked by intermediate middleboxes dropping ICMP "Fragmentation Needed" packets. Clamping TCP MSS (`TCPMSS --clamp-mss-to-pmtu`) forces TCP endpoints to negotiate segment sizes that fit comfortably within the 900-byte tunnel MTU.

### Why BBR, FQ, and 16MB Socket Buffers?
- **BBR Congestion Control**: Accurately models bandwidth-delay product (BDP) without collapsing transmission speeds upon transient packet loss.
- **Fair Queueing (`fq`)**: Paces TCP packets smoothly, eliminating burst-induced buffer bloat.
- **16MB Socket Buffers (`rmem_max`/`wmem_max`)**: Ensures ample window space across high-latency international routes (~70–120 ms RTT).

---

## 3. Verified Reference Performance

All measurements were taken using the **real production Shadowsocks client configuration** connecting through Iran `:9094`:

| Metric | Measured Result |
| :--- | :--- |
| **60-Second Real Sustained Average** | **129.24 Mbps** ($1,015.5\text{ MB}$ transferred) |
| **5-Minute Real Sustained Average** | **113.97 Mbps** ($4,406.35\text{ MB} / 4.41\text{ GB}$ transferred) |
| **10-Minute Extended Stability Average** | **120.51 Mbps** ($9,374.46\text{ MB} / 9.37\text{ GB}$ transferred) |
| **Peak 1s Instantaneous Speed** | **224.36 Mbps** |
| **Concurrent UDP / DNS Under Load** | **100% Operational** (0 dropped queries) |
| **Packet Loss Rate** | **0.0%** across all carrier links |

> [!NOTE]
> Performance numbers are benchmark reference results obtained on the production infrastructure. Actual throughput depends on host CPU capacity, hypervisor steal time, upstream network routing, provider ICMP handling, and path latency.

---

## 4. Repository Structure

```text
├── README.md                      # Architecture, design rationale, and benchmarks
├── .gitignore                     # Prevents keys, secrets, logs, and backups from tracking
├── docs/
│   ├── setup.md                   # Clean installation & deployment guide
│   ├── status.md                  # Detailed verification & test results
│   └── troubleshooting.md         # Diagnostic & healing procedures
├── iran/
│   ├── 99-tunnel-optimize.conf    # Sysctl kernel tuning (BBR, fq, 16MB buffers)
│   ├── iran-9094-relay            # Production multi-carrier flow-balancing relay script
│   ├── iran-9094-relay.service    # Systemd unit for automatic relay startup
│   ├── icmp9094-healthcheck       # Multi-carrier watchdog & auto-healing script
│   ├── icmp9094-healthcheck.timer # Periodic health check timer
│   ├── icmp9094-rollback          # Clean rollback script
│   ├── uninstall.sh               # Complete project-owned uninstaller
│   ├── setup-iran.sh              # Automated idempotent deployment script
│   ├── udp2raw-wg909*.conf.template # Carrier config templates for udp2raw
│   ├── udp2raw-wg909*.service     # Carrier systemd units with CPU affinity
│   ├── wg909*.conf.template       # WireGuard carrier interface templates (MTU 900)
│   └── wg-quick-udp2raw.conf      # Systemd drop-in override
└── foreign/
    ├── 99-tunnel-optimize.conf    # Sysctl kernel tuning (BBR, fq, 16MB buffers)
    ├── icmp9094-rollback          # Rollback script
    ├── uninstall.sh               # Complete project-owned uninstaller
    ├── setup-foreign.sh           # Automated idempotent deployment script
    ├── udp2raw-wg909*.conf.template # Server config templates for udp2raw
    ├── udp2raw-wg909*.service     # Server systemd units
    ├── wg909*.conf.template       # WireGuard interface templates (MTU 900)
    └── wg-quick-udp2raw.conf      # Systemd drop-in override
```

---

## 5. Quick Deployment Guide

See [`docs/setup.md`](docs/setup.md) for step-by-step instructions on deploying the architecture on a clean pair of servers.
