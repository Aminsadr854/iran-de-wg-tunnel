# Production architecture reference

The owner supplied these sustained measurements for the original three-carrier deployment:

| Duration | Average throughput |
| --- | --- |
| 60 seconds | 129.24 Mbps |
| 5 minutes | 113.97 Mbps |
| 10 minutes | 120.51 Mbps |

That deployment used three parallel WireGuard/udp2raw ICMP processes on an Iran host with three vCPUs, MTU 900, per-flow NAT balancing, BBR/fq, tuned socket limits and MSS clamping. It is the reference architecture retained in Release 2. Additional four/five-carrier experiments are not public installation defaults. Earlier single-carrier files remain available in Git history for provenance, not as supported installers.

These figures were not re-measured during Release 2 and do not demonstrate that the new installer has run on clean hosts. Provider handling of ICMP, CPU/virtualization, RTT, routing, loss and load materially affect results. Production addresses, administrative details and credentials are intentionally omitted.
