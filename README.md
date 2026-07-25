# Iran ↔ Germany WireGuard Tunnel (over udp2raw faketcp)

Private reference repo for a WireGuard tunnel between an Iran-based server and a
Germany-based server, used to forward traffic (TCP+UDP port 9093) from Iran to a
service running in Germany.

## Why this design

- **Plain GRE was tested first and does not work**: the network path drops GRE
  (IP protocol 47) entirely — packets leave the Iran host but never arrive at
  the Germany host. Confirmed via `tcpdump` on both ends.
- **Plain WireGuard (raw UDP) does not work either**: outbound UDP from the
  Iran host to the Germany host is filtered somewhere on the path (confirmed
  with raw `nc -u` tests on ports 51820 and 443 — packets leave Iran, never
  arrive at Germany). Inbound UDP from Germany to Iran works fine; only the
  Iran→Germany UDP direction is blocked.
- **TCP works cleanly in both directions** between the two hosts.
- **Solution**: WireGuard's UDP traffic is wrapped in `udp2raw` using
  `--raw-mode faketcp`, which disguises it as a normal TCP stream. This
  traverses the network path that blocks raw UDP.

## Topology

```
Client --TCP/UDP:9093--> Iran (91.108.145.130)
                            |
                            | DNAT: 9093 -> 10.20.20.2:9093
                            | via WireGuard tunnel (wg0)
                            | transport: udp2raw faketcp (Iran = client, DE = server)
                            v
                          Germany (104.167.24.112)
                            10.20.20.2:9093 (Xray/Shadowsocks service)
```

- WireGuard subnet: `10.20.20.0/30` — Iran = `10.20.20.1`, Germany = `10.20.20.2`
- udp2raw: Germany runs in **server** mode (`-s`), listening on `0.0.0.0:4096`
  (disguised as TCP), forwarding to local WireGuard on `127.0.0.1:443`.
  Iran runs in **client** mode (`-c`), listening on `127.0.0.1:4097`,
  connecting out to `104.167.24.112:4096`.
- WireGuard MTU is set to **1280**, not the default 1420. The udp2raw
  encapsulation overhead causes fragmentation/silent drops above ~1300-1400
  bytes on this path — this was diagnosed with `ping -M do -s <size>` and
  confirmed with `iperf3` (throughput collapsed to 0 until MTU was lowered).

## Known limitation

The raw, untunneled network path between these two specific hosts is itself
unstable at times (confirmed via `iperf3` without any tunnel — heavy
retransmits, bitrate swinging between 0 and 100+ Mbits/sec). This is an
underlying network/routing condition, not something fixable at the tunnel
config level. The tunnel setup here is correct and performs as well as the
underlying path allows.

## Files

- `iran/wg0.conf.template` — WireGuard config for the Iran side (client role for udp2raw)
- `iran/udp2raw-client.service` — systemd unit for udp2raw client on Iran
- `iran/iptables-rules.sh` — DNAT/MASQUERADE/FORWARD rules for port 9093 forwarding
- `iran/sysctl-forwarding.sh` — enables and persists `net.ipv4.ip_forward=1`
- `germany/wg0.conf.template` — WireGuard config for the Germany side
- `germany/udp2raw-server.service` — systemd unit for udp2raw server on Germany
- `docs/setup.md` — step-by-step reproduction guide
- `docs/troubleshooting.md` — diagnostic commands used, and what they revealed

## IMPORTANT — secrets are NOT included

All `.conf` files in this repo are **templates**. `PrivateKey`, `PublicKey`,
and the udp2raw `-k` shared secret are placeholders (`<...>`), not real
values. Real keys/secrets exist only on the two servers themselves
(`/etc/wireguard/wg0.conf`, `/etc/systemd/system/udp2raw.service`), not in
git — even in a private repo.

To regenerate keys when reproducing this setup:

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```
