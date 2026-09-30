# Iran–Foreign ICMP / WireGuard tunnel (port 9094)

Private operations repository for the tunnel between Iran `91.108.146.222` and
Foreign `2.31.14.109`.

## Current topology

```text
Client TCP/UDP :9094
  -> Iran public :9094
  -> narrow DNAT/SNAT rules
  -> wg9094 (10.77.94.1/30 -> 10.77.94.2/30, MTU 900)
  -> WireGuard UDP carried by udp2raw ICMP Echo
  -> Foreign wg9094 :9094
```

udp2raw is pinned to commit `4208db6e27c46f3ccec8b98722af7ec23bc62e73` and
uses ICMP mode with AES-128-CBC and HMAC-SHA1. The carrier peer endpoint is
reached through the physical default route; WireGuard installs only its
connected `/30` route. SSH and unrelated host traffic keep using their normal
routes.

## Status / acceptance boundary

- ICMP carrier and WireGuard link: verified.
- Iran TCP+UDP port forwarding: verified with temporary TCP/UDP echo probes;
  packet captures confirmed traffic on `wg9094` and outer ICMP on `eth0`.
- Automatic recovery after killing the Iran udp2raw process: verified in about
  11 seconds.
- **Shadowsocks application acceptance is not yet verified.** On the last
  inspection Foreign's Node-managed Xray was running, but it had no listener on
  `10.77.94.2:9094`. The Iran relay therefore had no matching application
  inbound at that moment. Do not treat L4 echo tests as Shadowsocks acceptance.

## Repository safety

This repository contains templates only. Never commit real WireGuard private
keys, the WireGuard PSK, udp2raw key, Shadowsocks keys, host passwords, or live
Xray configuration. Store those only in root-owned files on the servers.
See `.gitignore` for excluded secret patterns.

See [`docs/setup.md`](docs/setup.md) for reproducible deployment and
[`docs/status.md`](docs/status.md) for the observed validation results and
current application limitation.
