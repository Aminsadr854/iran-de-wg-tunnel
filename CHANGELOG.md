# Changelog

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
