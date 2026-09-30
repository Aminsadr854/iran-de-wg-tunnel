# Reproduce the port 9094 tunnel

This guide reproduces the isolated deployment described in the repository
README. It does not install or change an Xray/SS service. The Foreign endpoint
must separately have an application listening on `10.77.94.2:9094` for
application traffic to work.

## Values and paths

| Item | Iran | Foreign |
|---|---|---|
| Public address | `91.108.146.222` | `2.31.14.109` |
| WireGuard interface/address | `wg9094`, `10.77.94.1/30` | `wg9094`, `10.77.94.2/30` |
| WG carrier UDP endpoint | local udp2raw client `127.0.0.1:51895` | local WG listener `127.0.0.1:51894` |
| udp2raw carrier | client to Foreign `:42094` | ICMP server on `:42094` |
| Inner service | forwards TCP+UDP `:9094` | application must listen on `10.77.94.2:9094` |

WireGuard MTU is 900. Only `10.77.94.2/32` is routed through WireGuard;
neither host's default route is changed.

## Install and compile udp2raw

On both Ubuntu hosts:

```bash
apt-get update
apt-get install -y wireguard-tools build-essential git
git clone https://github.com/wangyu-/udp2raw-tunnel.git /usr/local/src/udp2raw-icmp9094
cd /usr/local/src/udp2raw-icmp9094
git checkout 4208db6e27c46f3ccec8b98722af7ec23bc62e73
make -j2
install -o root -g root -m 0755 udp2raw /usr/local/sbin/udp2raw-wg9094
```

The deployed build was compiled from this commit on each host. This revision
uses ICMP mode, AES-128-CBC, HMAC-SHA1, and a fresh random carrier secret.
Generate a new carrier secret for a new deployment; do not put it in Git.

## Generate and install WireGuard configuration

Generate distinct private keys on each server and a single shared WireGuard
PSK. Keep the private keys and PSK in root-only files. Fill the placeholders
in `iran/wg9094.conf.template` and `foreign/wg9094.conf.template`, install as
`/etc/wireguard/wg9094.conf`, and set mode `0600`.

Generate the udp2raw secret separately and fill the matching placeholder in
both udp2raw templates. Install as `/etc/udp2raw/wg9094.conf`, mode `0600`.
The udp2raw config file syntax is one complete option per line, with its value
on that same line where needed.

Install `udp2raw-wg9094.service` to
`/etc/systemd/system/udp2raw-wg9094.service` on both hosts. Install the
corresponding `wg-quick-udp2raw.conf` as
`/etc/systemd/system/wg-quick@wg9094.service.d/udp2raw.conf`.

Start Foreign first, then Iran:

```bash
systemctl daemon-reload
systemctl enable --now udp2raw-wg9094.service
systemctl enable --now wg-quick@wg9094.service
```

## Enable Iran TCP+UDP port forwarding

On Iran, install `iran/icmp9094-relay` as
`/usr/local/sbin/icmp9094-relay` (mode `0700`) and
`iran/icmp9094-relay.service` as
`/etc/systemd/system/icmp9094-relay.service`. The unit adds only specific
DNAT, SNAT, and forwarding rules for public `:9094`; it saves the original
`net.ipv4.ip_forward` value and restores it when stopped.

```bash
systemctl daemon-reload
systemctl enable --now icmp9094-relay.service
```

Install and enable `iran/icmp9094-healthcheck`,
`iran/icmp9094-healthcheck.service`, and
`iran/icmp9094-healthcheck.timer` at their corresponding `/usr/local/sbin`
and `/etc/systemd/system` paths. The timer probes once per minute after a
two-minute boot grace; three consecutive failures trigger recovery.

## Verify transport and routing

```bash
# On Iran
wg show wg9094
ping -I wg9094 -c 5 10.77.94.2
ip route get 2.31.14.109
iptables -t nat -vnL PREROUTING

# Capture the outer ICMP carrier on eth0 and the inner service packets on wg9094
tcpdump -ni eth0 icmp
tcpdump -ni wg9094 'tcp port 9094 or udp port 9094'
```

The route to Foreign's public IP must use Iran's physical interface/default
gateway. Do not add a WireGuard default route. The peer endpoint is protected
by the udp2raw shared secret and the WireGuard key pair/PSK.

An echo server can verify TCP+UDP forwarding, but this is only an L4 test. For
Shadowsocks acceptance, the Foreign application must listen on
`10.77.94.2:9094` and the test client must connect to Iran public `:9094`.

## Rollback

Keep a snapshot of `ip addr`, all route tables/rules, `iptables-save`,
`nft list ruleset`, systemd units, and existing application configuration
before deployment. The deployed rollback scripts are included here:

```bash
# Run on Iran, then on Foreign
/usr/local/sbin/icmp9094-rollback
```

Iran rollback removes only the `:9094` NAT/filter rules, restores the saved
`ip_forward` value, and disables the dedicated tunnel units. Foreign rollback
disables its dedicated WireGuard and udp2raw units. Neither script removes
Xray, Docker, SSH, or unrelated firewall rules.
