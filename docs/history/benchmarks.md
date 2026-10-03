# Production Architecture & Benchmark Reference

## Latest Verified Production Optimization Cycle (v2.1.0)

The following benchmark observations were recorded during a sustained production verification campaign on the optimized 3-carrier WireGuard-over-udp2raw ICMP architecture (MTU 1360, PersistentKeepalive 15, dynamic PMTU MSS clamping, BBR+fq, 16MB buffers):

| Metric / Scenario | Measured Observation |
| --- | --- |
| **10-Minute Sustained Average** | **130.17 Mbps** |
| **Peak Throughput** | **195.89 Mbps** |
| **Single-Flow TCP Throughput** | 56 – 61 Mbps |
| **4-Flow Parallel Throughput** | 144 – 145 Mbps |
| **Idle Carrier RTT** | ~112 ms |
| **Loaded Carrier RTT** | ~168 ms |
| **Post-Load UDP DNS Reliability** | 50/50 queries successful (0% loss) |

> [!NOTE]
> These measurements represent **production benchmark observations** under specific network, server, and transit conditions. They are **NOT** guaranteed performance metrics. Individual network paths, provider ICMP handling, server virtualization, physical latency, and regional network conditions will affect results.

## Historical Baseline Measurements (v2.0.0)

For historical provenance, the original deployment recorded the following sustained baseline:

| Duration | Average Throughput |
| --- | --- |
| 60 seconds | 129.24 Mbps |
| 5 minutes | 113.97 Mbps |
| 10 minutes | 120.51 Mbps |

## Architecture & Tuning Notes
- **WireGuard MTU**: Standardized at 1360 (optimized up from legacy 900 after path verification).
- **PersistentKeepalive**: 15 seconds (reduced from 25s for prompt NAT state refreshing).
- **MSS Clamping**: Dynamic `--clamp-mss-to-pmtu` across both Iran and Foreign firewall mangle chains. Conflicting static MSS rules were audited and removed.
- **Congestion Control**: BBR + Fair Queueing (`fq`) retained. (Cubic was tested and rejected due to lower throughput and higher buffer latency under load).
- **Queue Length**: `txqueuelen 1000` retained. (Experiments with `txqueuelen 5000` were tested and rejected to avoid bufferbloat).
