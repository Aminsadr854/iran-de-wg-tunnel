# Changelog

## v2.1.0 — Production Optimization & Reliability Release

### Verified Production Improvements
- **WireGuard MTU Increased (1360)**: Increased default WireGuard carrier MTU from 900 to 1360 across all three parallel carriers (`wg9094`, `wg9095`, `wg9096`) based on live production benchmark verification, significantly improving throughput while avoiding packet fragmentation.
- **Dynamic PMTU-Aware MSS Clamping**: Standardized dynamic `--clamp-mss-to-pmtu` across both Iran and Foreign endpoints in dedicated mangle chains (`IT2_MSS`). Conflicting static `--set-mss 1300` rules were audited and purged.
- **Optimized PersistentKeepalive (15s)**: Reduced WireGuard keepalive interval from 25s to 15s on carrier peers to maintain rapid state recovery across intermediate stateful firewalls.
- **Kernel Tuning Retained (BBR + fq)**: Retained verified BBR congestion control and Fair Queueing (`net.core.default_qdisc=fq`, `net.ipv4.tcp_congestion_control=bbr`), 16 MB socket buffers (`rmem_max`/`wmem_max = 16777216`), backlog (`netdev_max_backlog = 10000`), and `tcp_slow_start_after_idle = 0`.
- **Seamless v2.0.0 Upgrade Path**: Enhanced `tunnelctl upgrade` and `install.sh --upgrade` to detect existing v2.0.0 deployments, create timestamped backups outside Git, preserve generated private keys, PSKs, raw secrets, and endpoint configurations, and automatically migrate legacy MTU 900 settings to the optimized 1360 standard.
- **Foreign Local Egress MSS Clamping**: Ensured Foreign local application TCP return traffic traversing WireGuard interfaces is dynamically clamped to PMTU.
- **Idempotency & Secret Safety**: Validated zero-secret repository guarantee with automated pre-commit secret scans and strict placeholder standards.

### Explicitly Excluded / Rejected Experiments
- **Cubic Congestion Control**: Tested and rejected; BBR proved superior in throughput and latency under loaded transit conditions.
- **Queue Length txqueuelen 5000**: Tested and rejected; default `txqueuelen 1000` retained to prevent bufferbloat.

---

## v2.0.0 — Release 2: Portable Multi-Carrier ICMP Tunnel Installer

- Portable Foreign/Iran installer, interactive menu, non-interactive configuration and safe offline/host dry-runs.
- Production three-carrier ICMP architecture retained: independent WireGuard identities/PSKs, MTU 900, udp2raw xor/simple transport, conntrack TCP/UDP flow affinity.
- Automated protected one-way peer bootstrap and strong random secrets; no generated credential material in Git.
- Explicit Ubuntu LTS/Debian compatibility checks, resource/conflict detection and CPU-aware placement using actual usable CPU IDs.
- Project-owned systemd persistence/firewall chains, scoped MSS clamping, BBR/fq and socket tuning with conditional original-value restoration.
- `tunnelctl` status, independent health checks, bounded opt-in recovery, sanitized logs/diagnostics, key-preserving upgrade/repair, protected backup/restore and scoped uninstall.
- Transaction snapshots, injected-failure tests, strict data parsing, archive/secret-file validation and idempotency tests.
- Public README, architecture/configuration/operations/security/troubleshooting documentation and historical benchmark context.
- Full reachable Git-history/current-tree security review and Gitleaks scans found no literal credentials. Removed runtime production-specific files, addresses and assumptions; history preserved with a private bundle backup.
- No license selected on the owner's behalf; original repository had no LICENSE.
- Validation: static analysis, unit tests including real WireGuard key generation, mocked lifecycle tests and offline generator dry-runs. Clean-host live install not performed; production untouched.
