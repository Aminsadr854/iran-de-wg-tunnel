# Troubleshooting

## WireGuard ping fails

Check `systemctl status udp2raw-wg9094 wg-quick@wg9094`,
`journalctl -u udp2raw-wg9094`, and `wg show wg9094` on both servers. Confirm
the peer endpoint is the loopback udp2raw port on Iran and the WG server port
on Foreign. Confirm outer packets are ICMP on `eth0` and the public peer route
does not use `wg9094`.

## Iran :9094 is reachable but application traffic fails

Check Iran's `iptables -t nat -vnL PREROUTING` counters, then capture on both
WireGuard interfaces. On Foreign, verify the intended service listens on
`10.77.94.2:9094` for both TCP and UDP. A running Xray process alone is not
enough if it listens only on different ports or addresses.

## Recovery

The udp2raw service is configured with `Restart=always` and `RestartSec=5s`.
Iran's health timer requires three consecutive end-to-end ping failures before
restarting the carrier, WireGuard interface, and relay. A single lost ping
does not trigger a restart.
