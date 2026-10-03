# Configuration reference

The example contains documentation addresses, not production addresses. A live install requires your actual reachable public Foreign IPv4. `KEY=value` files are parsed as literal text with an allowlist; unknown/duplicate keys, quotes and shell expansion are rejected. No credentials belong in these public files. Generated secrets are separate root-only JSON/configuration under `/etc/icmp-tunnel`.

| Field | Default / meaning |
| --- | --- |
| ROLE | foreign or iran; must agree with --role |
| FOREIGN_PUBLIC_IP | Required reachable Foreign IPv4; supplied by bundle on Iran |
| PUBLIC_LISTEN_PORT | 9094, Iran TCP/UDP public endpoint |
| APPLICATION_PORT | 9094, Foreign application's TCP/UDP listener |
| CARRIER_COUNT | 3; 1–8 permitted explicitly, above three experimental |
| WIREGUARD_MTU | 1360 production verified; 576–1420 accepted (fallback to 900 if intermediate transit impairs large ICMP frames) |
| CARRIER_PORT_BASE | 42094; identifier/reserved UDP ports increment per carrier |
| WG_PORT_BASE | 51894 Foreign; Iran uses base + 1000; both increment per carrier |
| LOCAL_PORT_BASE | 53894 Iran udp2raw loopback listener; increments per carrier |
| TUNNEL_NETWORK | 10.203.0.0/24; aligned RFC1918 CIDR with at least one /30 per carrier |
| NETWORK_INTERFACE | Empty = physical peer/default route detection; override must agree with detected route |
| CPU_AFFINITY | yes; mapping uses sorted usable CPU IDs, wraps when needed; no disables pinning |
| SELF_HEAL | no; yes enables bounded independent carrier recovery |
| HEALTH_FAILURES | 3 consecutive unhealthy checks; range 2–20 |
| HEALTH_COOLDOWN | 300 seconds; range 60–86400, plus three attempts/hour cap |
| HANDSHAKE_MAX_AGE | 180 seconds; range 120–86400; keepalive is 15 seconds on Iran |
| PEER_FILE | Iran secret pairing JSON path, absolute path recommended |

Names are fixed `wg9094` onward. The network allocator assigns Iran/Foreign addresses at offsets 1/2 in each consecutive /30; the unused portions of the CIDR are not routed. Preflight checks the used subnets against every route table and address, not only the global default. Port ranges must be nonoverlapping, including Iran's derived WireGuard range and the application ports.

Iran may override local CPU/health/interface fields, but cannot change pairing-critical fields. Generate a new pair on fresh installations to change layout/count/MTU. Public settings shown by `tunnelctl config` are informational; do not edit the secret state JSON directly. Repair and upgrade preserve them. Changing existing runtime settings is not an arbitrary migration facility in this release.
