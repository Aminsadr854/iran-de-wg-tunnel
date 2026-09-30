# Observed deployment status

Recorded 2026-09-30 during deployment on Iran `91.108.146.222` and Foreign
`2.31.14.109`.

| Check | Result |
|---|---|
| udp2raw ICMP handshake | PASS |
| WireGuard `wg9094` | PASS, MTU 900 |
| Inner WireGuard ping | PASS, 0% loss in the short verification |
| Iran TCP+UDP DNAT/SNAT to Foreign WG address | PASS with temporary echo listener |
| Physical outer ICMP and inner WG port 9094 capture | PASS |
| Recovery after Iran udp2raw process kill | PASS, about 11 seconds |
| Default routes / SSH path | unchanged; public peer route uses `eth0` |
| Shadowsocks application through Iran `:9094` | NOT VERIFIED |

At the last diagnostic, Foreign's Node-managed Xray process was active, but its
listeners did not include `10.77.94.2:9094`; a direct TCP connect to that
WireGuard address returned connection refused. The separate Node-managed
service must be configured to accept the supplied Shadowsocks 2022 credentials
on that WireGuard address/port before claiming application-level success.

The temporary echo process and packet captures were removed after testing.
