# Troubleshooting Log

Diagnostic steps taken while building this tunnel, in case the same symptoms
show up again.

## Symptom: plain GRE tunnel — 0% connectivity

```bash
ip tunnel add gre1 mode gre local <LOCAL_IP> remote <REMOTE_IP> ttl 255
ip addr add 10.10.10.1/30 dev gre1
ip link set gre1 up
ping 10.10.10.2   # 100% packet loss
```

Diagnosis: captured on the sending side's physical interface —

```bash
tcpdump -i eth0 proto gre -n
```

GRE packets were confirmed leaving the Iran host. Capturing the same filter
on the Germany host's interface showed **zero** GRE packets arriving.
Local iptables/nftables on both ends had no rules blocking anything
(`iptables -L -n -v` — all ACCEPT, empty chains). Conclusion: GRE (IP
protocol 47) is filtered somewhere on the network path — provider-level
firewall/security group, not something fixable on either host.

## Symptom: plain WireGuard (raw UDP) — 0% connectivity, both ports 51820 and 443

Same pattern as GRE: `wg show` showed bytes sent but 0 bytes received on
both ends. Isolated from WireGuard entirely using raw `nc`:

```bash
# On Germany:
nc -u -l 443

# On Iran:
echo test | nc -u -w2 <GERMANY_IP> 443
# -> nothing received on Germany
```

Reverse direction test (Germany -> Iran) worked fine. Conclusion: outbound
UDP specifically from Iran to Germany is filtered on the path. Inbound UDP to
Iran, and UDP in the other direction, work normally. This makes any raw UDP
protocol (including plain WireGuard) unusable for the Iran->Germany leg.

TCP was tested and confirmed working cleanly in both directions with `nc`
(no `-u` flag).

## Fix: udp2raw in faketcp mode

Wraps WireGuard's UDP traffic to look like a TCP stream, which traverses the
path that blocks raw UDP. See main setup guide.

## Symptom: iperf3 throughput collapses to 0 mid-transfer after enabling udp2raw

```
[  5]   0.00-1.00   sec  69.5 KBytes   569 Kbits/sec
[  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec
[  5]   2.00-8.00   sec  0.00 Bytes  0.00 bits/sec  (repeats)
```

Diagnosis: MTU mismatch. WireGuard was left at the default MTU (1420), but
the udp2raw faketcp encapsulation adds overhead that pushes real packets
over the effective path MTU, causing large packets to be silently dropped.
Confirmed with:

```bash
ping -M do -s 1400 -c 3 10.20.20.2   # "message too long, mtu=1420" (local truncation)
ping -M do -s 1200 -c 3 10.20.20.2   # 0% loss
ping -M do -s 1000 -c 3 10.20.20.2   # 0% loss
```

Fix: lowered `MTU = 1280` in both `wg0.conf` files, then restarted both
`udp2raw` services (server first) followed by both `wg-quick@wg0` services.
After this, iperf3 showed sustained (non-zero) throughput.

## Symptom: after restarting wg-quick@wg0, tunnel goes to 0% handshake/loss

Restarting WireGuard alone doesn't always work — the udp2raw faketcp
connection state can get out of sync. Fix: restart in this order:

```bash
# Germany first:
systemctl restart udp2raw
systemctl restart wg-quick@wg0

# Then Iran:
systemctl restart udp2raw
systemctl restart wg-quick@wg0
```

## Baseline network instability (not a tunnel bug)

Running `iperf3` directly between the two hosts with **no tunnel at all**
showed the same kind of instability seen through the tunnel — bitrate
swinging between 0 and 100+ Mbits/sec, thousands of TCP retransmits over a
short test. This means some of the tunnel's real-world throughput variance
is inherent to the network path between these specific hosts/providers at
this time, not a configuration problem. Re-run a raw (untunneled) `iperf3`
test between the two hosts before assuming the tunnel itself regressed.
