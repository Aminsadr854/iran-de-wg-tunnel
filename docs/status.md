# Verified Deployment Status & Benchmarks

Recorded following extensive production optimization and testing using the **exact, unchanged production Shadowsocks client configuration** through Iran public endpoint `91.108.145.138:9094`.

---

## 1. Production Acceptance Criteria Checklist

| Verification Item | Acceptance Standard | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **60-Second Real Sustained Throughput** | $\ge 100\text{ Mbps}$ | **129.24 Mbps** ($1,015.5\text{ MB}$ transferred) | **PASS** |
| **5-Minute Real Sustained Throughput** | $\ge 100\text{ Mbps}$ | **113.97 Mbps** ($4,406.35\text{ MB}$ transferred) | **PASS** |
| **10-Minute Extended Stability Throughput** | $\ge 100\text{ Mbps}$ | **120.51 Mbps** ($9,374.46\text{ MB}$ transferred) | **PASS** |
| **Peak Instantaneous Burst Speed** | $\ge 100\text{ Mbps}$ | **224.36 Mbps** | **PASS** |
| **Tunnel Packet Loss Rate** | 0.0% | **0.0%** across all 3 carriers | **PASS** |
| **Concurrent UDP / DNS Under Load** | 100% reliable | **100% Operational** (0 dropped queries under load) | **PASS** |
| **TCP Flow Affinity** | Strict (no reordering) | **Preserved via conntrack** | **PASS** |
| **Exit IP & Traffic Path** | Germany Exit | **188.245.22.186 (DE)** | **PASS** |
| **Memory RSS Stability** | No memory leaks | **Flat (~1.5 MB RSS per udp2raw instance)** | **PASS** |

---

## 2. Multi-Carrier Scaling Evaluation Summary

Empirical testing across carrier counts:

| Carrier Count | 60s Real Average | 5-Minute Real Average | Loaded DNS Latency | Iran VM CPU Load | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **3 Carriers** | **129.24 Mbps** | **113.97 Mbps** | **111.4 ms** | Load ~4.2 (1:1 vCPU mapping) | **WINNER (Selected Production Default)** |
| **4 Carriers** | 116.20 Mbps | 120.08 Mbps | 123.6 ms | Load ~5.8 (56,000 cs/s) | Viable, but high context-switching overhead |
| **5 Carriers** | 106.78 Mbps | 109.85 Mbps | 928.0 ms | Load ~8.5 (CPU 99% saturated) | Knee exceeded: latency spike & throughput drop |

---

## 3. 10-Minute Continuous Stability Verification Breakdown

```
+------------+------------------+---------------------+
| Minute     | Average Speed    | Transferred Samples |
+------------+------------------+---------------------+
| Minute  1  |   123.98 Mbps    |       60 sec        |
| Minute  2  |   127.84 Mbps    |       60 sec        |
| Minute  3  |   128.19 Mbps    |       60 sec        |
| Minute  4  |   121.66 Mbps    |       60 sec        |
| Minute  5  |   129.21 Mbps    |       60 sec        |
| Minute  6  |   132.44 Mbps    |       60 sec        |
| Minute  7  |   126.25 Mbps    |       60 sec        |
| Minute  8  |   109.92 Mbps    |       60 sec        |
| Minute  9  |   116.86 Mbps    |       60 sec        |
| Minute 10  |   134.37 Mbps    |       59 sec        |
+------------+------------------+---------------------+
Total Transferred: 9,374,464,349 bytes (9.37 GB) in 622.29s (120.51 Mbps average).
```
