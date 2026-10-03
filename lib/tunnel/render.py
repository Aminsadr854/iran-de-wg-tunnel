"""Pure generators; transport parameters match the production baseline."""
from .config import cpu_mapping

SYSCTL = {'net.core.default_qdisc':'fq', 'net.ipv4.tcp_congestion_control':'bbr',
          'net.core.rmem_max':'16777216', 'net.core.wmem_max':'16777216',
          'net.ipv4.tcp_rmem':'4096 87380 16777216', 'net.ipv4.tcp_wmem':'4096 65536 16777216',
          'net.core.netdev_max_backlog':'10000', 'net.ipv4.tcp_slow_start_after_idle':'0',
          'net.ipv4.ip_forward':'1'}
PREFIX = 'IT2'
CHAINS = [('nat','IT2_DNAT','PREROUTING'), ('nat','IT2_SNAT','POSTROUTING'),
          ('filter','IT2_FWD','FORWARD'), ('filter','IT2_INPUT','INPUT'),
          ('mangle','IT2_MSS','FORWARD')]

def firewall_rules(c, carriers):
    """Only first packet traverses NAT chains; conntrack pins TCP and UDP flows."""
    rules = []
    def add(table, chain, *args):
        rules.append((table,chain,list(map(str,args))))
    iface = c['NETWORK_INTERFACE']
    port = c['PUBLIC_LISTEN_PORT']
    for x in carriers:
        # Raw PF_PACKET receives before INPUT. Suppress kernel echo only for the
        # carrier's ICMP identifier (source port), leaving normal ping available.
        match = ['-i',iface,'-p','icmp','--icmp-type', '8' if c['ROLE']=='foreign' else '0',
                 '-m','u32','--u32',f'0>>22&0x3C@4>>16&0xFFFF={x["raw_port"]}']
        if c['ROLE']=='iran':
            match += ['-s',c['FOREIGN_PUBLIC_IP']]
        add('filter','IT2_INPUT',*match,'-j','DROP')
        # WireGuard UDP is accessible only from local udp2raw. The public service
        # itself is admitted only on WG, never broadly opened on the physical NIC.
        wgport = x['wg_port'] if c['ROLE']=='foreign' else x['wg_port']+1000
        add('filter','IT2_INPUT','-i','lo','-p','udp','--dport',wgport,'-j','ACCEPT')
        add('filter','IT2_INPUT','!','-i','lo','-p','udp','--dport',wgport,'-j','DROP')
        add('filter','IT2_INPUT','-i',x['name'],'-p','icmp','-j','ACCEPT')
        if c['ROLE']=='foreign':
            for proto in ('tcp','udp'):
                add('filter','IT2_INPUT','-i',x['name'],'-d',x['foreign_ip'],'-p',proto,
                    '--dport',c['APPLICATION_PORT'],'-j','ACCEPT')
            for direction in ('-i','-o'):
                add('mangle','IT2_MSS',direction,x['name'],'-p','tcp','--tcp-flags','SYN,RST','SYN',
                    '-j','TCPMSS','--clamp-mss-to-pmtu')
    if c['ROLE']=='iran':
        for proto in ('tcp','udp'):
            for i,x in enumerate(carriers):
                args = ['-i',iface,'-m','addrtype','--dst-type','LOCAL','-p',proto,'--dport',port]
                if proto=='tcp':
                    args += ['--syn']
                remaining = len(carriers)-i
                if remaining > 1:
                    args += ['-m','statistic','--mode','nth','--every',str(remaining),'--packet','0']
                add('nat','IT2_DNAT',*args,'-j','DNAT','--to-destination',f'{x["foreign_ip"]}:{c["APPLICATION_PORT"]}')
        for x in carriers:
            dev = x['name']
            add('nat','IT2_SNAT','-o',dev,'-d',x['foreign_ip'],'-m','conntrack','--ctstate','DNAT',
                '-j','SNAT','--to-source',x['iran_ip'])
            for proto in ('tcp','udp'):
                add('filter','IT2_FWD','-i',iface,'-o',dev,'-d',x['foreign_ip'],
                    '-p',proto,'--dport',c['APPLICATION_PORT'],'-m','conntrack','--ctstate','DNAT','-j','ACCEPT')
            add('filter','IT2_FWD','-i',dev,'-o',iface,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
            for direction in ('-i','-o'):
                add('mangle','IT2_MSS',direction,dev,'-p','tcp','--tcp-flags','SYN,RST','SYN',
                    '-j','TCPMSS','--clamp-mss-to-pmtu')
    # No terminal DROP: unrelated traffic returns to the host's existing policy.
    return rules

def wireguard(c, x):
    foreign = c['ROLE']=='foreign'
    local, peer = (x['foreign_ip'],x['iran_ip']) if foreign else (x['iran_ip'],x['foreign_ip'])
    port = x['wg_port'] if foreign else x['wg_port']+1000
    result = f'''[Interface]
Address = {local}/30
ListenPort = {port}
PrivateKey = {x['private']}
MTU = {c['WIREGUARD_MTU']}
Table = off

[Peer]
PublicKey = {x['peer_public']}
PresharedKey = {x['psk']}
AllowedIPs = {peer}/32
'''
    if not foreign:
        result += f'Endpoint = 127.0.0.1:{x["local_port"]}\nPersistentKeepalive = 15\n'
    return result

def udp2raw(c,x):
    if c['ROLE']=='foreign':
        result = f'-s\n-l 0.0.0.0:{x["raw_port"]}\n-r 127.0.0.1:{x["wg_port"]}\n'
    else:
        result = (f'-c\n-l 127.0.0.1:{x["local_port"]}\n-r {c["FOREIGN_PUBLIC_IP"]}:{x["raw_port"]}\n'
                  f'--source-ip {c["LOCAL_IP"]}\n--source-port {x["raw_port"]}\n')
    return (result + f'-k {x["raw_secret"]}\n--raw-mode icmp\n--cipher-mode xor\n--auth-mode simple\n'
            f'--log-level 2\n--disable-color\n--dev {c["NETWORK_INTERFACE"]}\n--sock-buf 10240\n--force-sock-buf\n')

def units(c, carriers, cpus):
    units = {}
    mapping = cpu_mapping(len(carriers),cpus)
    for i,x in enumerate(carriers):
        dev=x['name']
        affinity = f'CPUAffinity={mapping[i]}\n' if c['CPU_AFFINITY']=='yes' else ''
        units[f'icmp-tunnel-raw-{dev}.service'] = f'''[Unit]
Description=ICMP Tunnel udp2raw {dev}
Wants=network-online.target
After=network-online.target icmp-tunnel-firewall.service
Requires=icmp-tunnel-firewall.service
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/opt/icmp-tunnel/bin/udp2raw --conf-file /etc/icmp-tunnel/raw/{dev}.conf
Restart=on-failure
RestartSec=10
{affinity}Nice=-10
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''
        # udp2raw's parser can print secret argv even with log-level 2. Output is
        # suppressed at systemd; safe lifecycle/failure info remains in journald.
        units[f'icmp-tunnel-wg-{dev}.service'] = f'''[Unit]
Description=ICMP Tunnel WireGuard {dev}
Wants=network-online.target icmp-tunnel-raw-{dev}.service
After=network-online.target icmp-tunnel-raw-{dev}.service icmp-tunnel-firewall.service
Requires=icmp-tunnel-firewall.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up /etc/icmp-tunnel/wg/{dev}.conf
ExecStop=/usr/bin/wg-quick down /etc/icmp-tunnel/wg/{dev}.conf
TimeoutStartSec=45

[Install]
WantedBy=multi-user.target
'''
    units['icmp-tunnel-firewall.service'] = '''[Unit]
Description=ICMP Tunnel owned firewall chains
Wants=network-online.target
After=network-online.target systemd-sysctl.service
Before=icmp-tunnel-health.timer

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/tunnelctl _firewall start
ExecStop=/usr/local/bin/tunnelctl _firewall stop
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
'''
    units['icmp-tunnel-health.service'] = '''[Unit]
Description=ICMP Tunnel independent carrier health monitor
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/tunnelctl health --recover
TimeoutStartSec=90
'''
    units['icmp-tunnel-health.timer'] = '''[Unit]
Description=ICMP Tunnel periodic health check

[Timer]
OnBootSec=120
OnUnitActiveSec=60
RandomizedDelaySec=10
Persistent=true

[Install]
WantedBy=timers.target
'''
    if c['ROLE'] == 'iran' and len(c.get('FOREIGN_ENDPOINTS', '').split()) > 1:
        units['icmp-tunnel-failover.service'] = '''[Unit]
Description=ICMP Tunnel automated endpoint failover daemon
Wants=network-online.target
After=network-online.target icmp-tunnel-firewall.service

[Service]
Type=simple
ExecStart=/usr/local/bin/tunnelctl failover daemon
Restart=always
RestartSec=15
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
'''
    return units
