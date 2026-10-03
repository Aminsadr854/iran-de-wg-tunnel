# Troubleshooting

Use `sudo tunnelctl status`, then `sudo tunnelctl health`, `sudo tunnelctl logs` and `sudo tunnelctl diagnostics`. Health failure codes describe service, routing, probe and handshake problems independently. Do not publish `/etc/icmp-tunnel`, pairing files or backups.

| Symptom | Investigation and action |
| --- | --- |
| No WireGuard handshake | Confirm both endpoints installed from the same bundle; check each raw/WG state and peer physical route in diagnostics. Re-pair if credentials/layout disagree. Do not copy private keys into issues. |
| udp2raw not starting | Check status/journald lifecycle and systemd Result/ExecMainStatus. Check occupied raw UDP/loopback ports, physical interface, CAP_NET_RAW/NET_ADMIN and pinned build. Output is suppressed intentionally to avoid upstream credential logs. |
| ICMP blocked | Verify provider and host firewalls allow both Echo request and reply. Ping alone cannot verify tunneled payload handling. Health probes inside each WG interface test the actual carrier. Identifier-rewriting NAT is unsupported. |
| TCP works but UDP fails | Check application has a UDP listener on **every** Foreign carrier address and port. Confirm Iran's public UDP allowance and application protocol. NAT rules pin UDP by conntrack flow; application-level UDP support is still required. |
| DNS failure | This is a port relay, not a DNS server. Check the application's UDP/DNS mode, its upstream resolver and its client configuration. Concurrent TCP should not change an existing UDP flow's carrier. |
| Low throughput / high CPU | Compare usable CPU count, carrier CPU affinity and provider steal/load. One connection stays on one carrier. Benchmark multiple flows on non-production hosts; keep default three carriers and MTU 1360. Reference speeds are not guaranteed. |
| High RTT | Check peer route, provider ICMP handling, loss and congestion. More carriers may increase CPU contention. Do not restart all carriers on one slow probe. |
| MTU stalls | Verify status reports matching MTU (1360 default, or 900 fallback) on both ends and diagnostics includes scoped MSS rules with dynamic PMTU clamping (`--clamp-mss-to-pmtu`). If intermediate transit impairs frames larger than 900 bytes, set `WIREGUARD_MTU=900`. UDP applications must respect payload size; MSS only applies to TCP. |
| iptables/nftables conflicts | Preflight refuses active UFW/firewalld and independent nft tables. Arrange a persistent integration before installation. iptables raw/custom policy can interfere despite compatibility checks. Never flush global rules to troubleshoot. |
| Port/resource conflict | Choose different base/application ports or tunnel network on Foreign before generating the bundle. Never kill unrelated listeners/interfaces. A reserved ICMP socket is UDP in the pinned implementation. |
| One carrier failure | Inspect that carrier's timestamps/RX/TX, then `sudo tunnelctl restart-carrier 2` if appropriate. Healthy carriers remain independent. Existing flows on the failed carrier can break; no live failover is claimed. |
| Service fails after reboot | Check firewall/raw/WG systemd states, network-online implementation and the physical peer route. `sudo tunnelctl repair` makes a backup and reapplies owned resources. A wrong source address/interface after network changes must be corrected before repair. |
| Shared firewall/sysctl missing | Health withholds automatic recovery. `tunnelctl repair` backs up and re-renders project resources, after preflight. Inspect competing configuration managers first. |
| Interrupted installation/update | See [operations](operations.md). Inspect transaction marker and root-only snapshot; don't overwrite them or rerun blind installation. |

Useful safe commands:

```bash
sudo tunnelctl restart-carrier 1
sudo systemctl show icmp-tunnel-raw-wg9094.service -p ActiveState -p Result -p ExecMainStatus
sudo tunnelctl repair
sudo sh -c 'umask 077; tunnelctl diagnostics > /root/tunnel-diagnostics.txt'
```

Diagnostics include addresses/topology; review before filing an issue. Include OS/kernel, installer version, whether preflight succeeded and sanitized failing carrier information. Avoid packet captures of user traffic; captures can contain sensitive metadata or payloads.
