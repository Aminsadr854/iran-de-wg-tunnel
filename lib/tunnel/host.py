"""Host inspection and narrowly scoped operating-system operations."""
import ipaddress
import json
import os
import platform
import shutil
import shlex
import socket
import subprocess
from pathlib import Path
from .config import Error, layout, supported_os
from .render import CHAINS, SYSCTL, firewall_rules

ETC = Path('/etc/icmp-tunnel')
APP = Path('/opt/icmp-tunnel')
VAR = Path('/var/lib/icmp-tunnel')
SYSFILE = Path('/etc/sysctl.d/90-icmp-tunnel.conf')
UNITDIR = Path('/etc/systemd/system')
CLI = Path('/usr/local/bin/tunnelctl')
UPSTREAM = 'https://github.com/wangyu-/udp2raw-tunnel.git'
UPSTREAM_REV = '4208db6e27c46f3ccec8b98722af7ec23bc62e73'
PACKAGES = ['python3','iproute2','iptables','nftables','wireguard-tools','procps','kmod',
            'iputils-ping','build-essential','git','ca-certificates','util-linux']

def run(args, check=True, input=None, timeout=60):
    try:
        p = subprocess.run([str(x) for x in args], input=input, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           env={**os.environ,'LC_ALL':'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise Error(f'{args[0]} could not run or timed out.') from None
    if check and p.returncode:
        # Do not propagate subprocess output: wg-quick/udp2raw may contain secrets.
        raise Error(f'{args[0]} failed (exit {p.returncode}); inspect service status or package availability.')
    return p

def os_info():
    info={}
    for line in Path('/etc/os-release').read_text().splitlines():
        k,sep,v=line.partition('=')
        if sep:
            info[k]=v.strip('"')
    return info

def ip_json(*args):
    return json.loads(run(['ip','-j','-4',*args]).stdout)

def physical_network(c):
    destination = c['FOREIGN_PUBLIC_IP'] if c['ROLE']=='iran' else '1.1.1.1'
    routes=ip_json('route','get',destination)
    if not routes or not routes[0].get('dev') or not routes[0].get('prefsrc'):
        raise Error('Cannot determine physical route/source IPv4. Configure a working IPv4 default route.')
    r=routes[0]
    iface=c['NETWORK_INTERFACE'] or r['dev']
    if iface != r['dev'] or iface.startswith(('wg','tun','tap')):
        raise Error('Peer route must use the selected physical interface; recursive/VPN routing is unsupported.')
    if not Path('/sys/class/net',iface).exists():
        raise Error('Selected physical interface does not exist.')
    details=json.loads(run(['ip','-j','-d','link','show','dev',iface]).stdout)
    kind=details[0].get('linkinfo',{}).get('info_kind','')
    if kind in ('wireguard','tun','gre','gretap','ipip','sit','vxlan','geneve','erspan'):
        raise Error('Peer route uses another tunnel interface; a physical IPv4 path is required.')
    c.update(NETWORK_INTERFACE=iface, LOCAL_IP=r['prefsrc'], PHYSICAL_ROUTE=r)
    return r

def preflight(c, existing=False):
    info=os_info()
    print(f'OS: {info.get("PRETTY_NAME")} | kernel: {platform.release()} | architecture: {platform.machine()}')
    supported_os(info)
    if platform.machine() not in ('x86_64','aarch64'):
        raise Error('Supported architectures: x86_64 and aarch64 (native udp2raw build).')
    nums=platform.release().split('-')[0].split('.')
    if tuple(map(int,nums[:2])) < (5,6):
        raise Error('Kernel >= 5.6 with native WireGuard support is required.')
    cpus=sorted(os.sched_getaffinity(0))
    ram=next(x for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:'))
    print(f'Usable CPU IDs: {cpus} | {ram}')
    if c['CARRIER_COUNT'] > len(cpus):
        print('WARNING: fewer CPUs than carriers; carriers will safely share available CPU IDs. Three remains the default.')
    if not Path('/run/systemd/system').is_dir():
        raise Error('A booted systemd host is required. Containers without systemd are unsupported.')
    for command in ('ip','systemctl','apt-get'):
        if not shutil.which(command):
            raise Error(f'{command} is required before preflight (install iproute2/systemd/apt).')
    physical_network(c)
    print(f'Primary interface: {c["NETWORK_INTERFACE"]} | local IPv4: {c["LOCAL_IP"]}')
    print(f'Foreign public IPv4: {c["FOREIGN_PUBLIC_IP"]} | physical route: {c["PHYSICAL_ROUTE"]}')
    print('NAT/cloud firewall: public mapping and ICMP reachability require an administrator check; Internet access alone cannot verify them.')
    print(f'WireGuard tools: {shutil.which("wg") or "will install"}')
    print('Required packages: '+', '.join(PACKAGES))
    print('Required ports: public TCP+UDP '+str(c['PUBLIC_LISTEN_PORT'])+'; ICMP identifiers '+
          ','.join(str(x['raw_port']) for x in layout(c)))
    for service in ('ufw','firewalld'):
        if run(['systemctl','is-active',service],check=False).returncode==0:
            raise Error(f'{service} is active; arrange persistent project-compatible firewall integration first. It will not be disabled.')
    if shutil.which('iptables'):
        print('Firewall backend: '+run(['iptables','--version']).stdout.strip())
        for table,chain,_ in CHAINS:
            if not existing and run(['iptables','-w','5','-t',table,'-S',chain],check=False).returncode==0:
                raise Error(f'Conflicting firewall chain {chain}; no rules changed.')
    if shutil.which('nft'):
        tables=run(['nft','-j','list','tables'])
        for entry in json.loads(tables.stdout).get('nftables',[]):
            t=entry.get('table',{})
            if t and not (t.get('family')=='ip' and t.get('name') in ('filter','nat','mangle','raw','security')):
                raise Error('Independent nftables tables detected. Multiple firewall owners are unsupported; no rules changed.')
    if not existing:
        for p in (ETC, APP, SYSFILE, CLI):
            if p.exists() or p.is_symlink():
                raise Error(f'Conflicting existing path {p}; use management commands for a recognized installation.')
        if VAR.exists() or VAR.is_symlink():
            marker=VAR/'owner.json'
            try:
                retained=(not VAR.is_symlink() and VAR.stat().st_uid==0
                          and VAR.stat().st_mode & 0o077 == 0
                          and json.loads(marker.read_text())=={'owner':'icmp-tunnel-managed-v2'}
                          and set(p.name for p in VAR.iterdir()) <= {'owner.json','backups'})
            except (OSError,ValueError):
                retained=False
            if not retained:
                raise Error('Existing runtime directory is not an owned retained-backup directory; no files changed.')
            print('Recognized retained secret backups: kept during reinstall.')
        names = [f'icmp-tunnel-{kind}-{x["name"]}.service' for x in layout(c) for kind in ('raw','wg')]
        names += ['icmp-tunnel-firewall.service','icmp-tunnel-health.service','icmp-tunnel-health.timer']
        for name in names:
            if (UNITDIR/name).exists() or run(['systemctl','show',name,'--property=LoadState','--value'],check=False).stdout.strip() not in ('not-found',''):
                raise Error(f'Conflicting systemd unit {name}; no services stopped.')
        for x in layout(c):
            if Path('/sys/class/net',x['name']).exists() or Path('/etc/wireguard',x['name']+'.conf').exists():
                raise Error(f'Conflicting interface/configuration {x["name"]}.')
        # Inspect routes in every table plus all interface networks; reserve /30s only.
        occupied=[]
        for r in ip_json('route','show','table','all'):
            dst=r.get('dst','default')
            if dst != 'default':
                occupied.append(ipaddress.IPv4Network(dst,strict=False))
        for a in ip_json('address','show'):
            for v in a.get('addr_info',[]):
                occupied.append(ipaddress.IPv4Network(f'{v["local"]}/{v["prefixlen"]}',strict=False))
        for x in layout(c):
            sub=ipaddress.IPv4Network(x['iran_ip']+'/30',strict=False)
            if any(sub.overlaps(net) for net in occupied):
                raise Error('Tunnel subnet overlaps an existing route/interface. Change TUNNEL_NETWORK on Foreign.')
        for x in layout(c):
            # ICMP mode reserves UDP socket ports in the pinned upstream code.
            ports = [('udp',x['raw_port']), ('udp', x['wg_port'] if c['ROLE']=='foreign' else x['wg_port']+1000)]
            if c['ROLE']=='iran':
                ports += [('udp',x['local_port'])]
            for proto,port in ports:
                check_port(proto,port)
        if c['ROLE']=='iran':
            for proto in ('tcp','udp'):
                check_port(proto,c['PUBLIC_LISTEN_PORT'])
            if shutil.which('iptables-save'):
                nat=run(['iptables-save','-t','nat']).stdout
                if nat_port_conflict(nat,c['PUBLIC_LISTEN_PORT']):
                    raise Error('Existing DNAT/REDIRECT claims the public relay port; choose another port. No NAT rule changed.')
        print('Conflicting interfaces, units, routes, paths and ports: none detected.')
    else:
        print('Recognized installation: repair/upgrade preserves keys and public configuration.')
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); s.close()
        s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.close()
    except OSError:
        raise Error('CAP_NET_RAW/CAP_NET_ADMIN and raw/PF_PACKET sockets are required; restricted containers are unsupported.') from None
    caps=next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    if not int(caps,16) & (1 << 12):
        raise Error('CAP_NET_ADMIN is required for WireGuard and firewall configuration.')
    print('Raw IP/PF_PACKET sockets and CAP_NET_ADMIN: available')
    missing=[]
    for module in ('wireguard','tcp_bbr','sch_fq','nf_conntrack','iptable_nat','iptable_mangle','xt_statistic','xt_TCPMSS','xt_u32','xt_addrtype','xt_conntrack'):
        if Path('/sys/module',module).exists():
            continue
        if not shutil.which('modprobe') or run(['modprobe','-n',module],check=False).returncode:
            missing.append(module)
    if missing:
        raise Error('Required kernel features unavailable: '+', '.join(missing)+'. Install your distribution kernel/modules package and reboot; preflight made no changes.')
    for key in SYSCTL:
        if not Path('/proc/sys',key.replace('.','/')).exists():
            raise Error(f'Required sysctl unavailable: {key}.')
    # HTTPS connection confirms a usable physical Internet path, not carrier connectivity.
    try:
        with socket.create_connection(('github.com',443),timeout=8):
            pass
    except OSError:
        raise Error('Cannot connect to github.com:443; package/source installation needs Internet connectivity.') from None
    print('Public connectivity: github.com:443 reachable | IPv4 forwarding: '+Path('/proc/sys/net/ipv4/ip_forward').read_text().strip())
    return cpus

def check_port(proto,port):
    kind=socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET,kind) as sock:
        try:
            sock.bind(('0.0.0.0',port))
        except OSError:
            raise Error(f'{proto.upper()} port {port} is occupied; no unrelated service will be stopped.') from None

def install_packages():
    print('Installing distribution packages; packages are retained on rollback/uninstall.')
    run(['apt-get','update'],timeout=600)
    run(['apt-get','install','-y',*PACKAGES],timeout=900)
    for module in ('wireguard','tcp_bbr','sch_fq','nf_conntrack','iptable_nat','iptable_mangle','xt_statistic','xt_TCPMSS','xt_u32','xt_addrtype','xt_conntrack'):
        run(['modprobe',module])
    if 'bbr' not in run(['sysctl','-n','net.ipv4.tcp_available_congestion_control']).stdout.split():
        raise Error('BBR is unavailable after loading tcp_bbr.')

def ipt(*args,check=True):
    return run(['iptables','-w','5',*args],check=check)

def ensure_rule(table, chain, args, position=None):
    if ipt('-t',table,'-C',chain,*args,check=False).returncode:
        command=['-t',table,'-I' if position else '-A',chain]
        if position:
            command.append(str(position))
        ipt(*command,*args)

def firewall_start(state):
    c,xs=state['config'],state['carriers']
    for table,chain,base in CHAINS:
        if ipt('-t',table,'-S',chain,check=False).returncode:
            ipt('-t',table,'-N',chain)
        ipt('-t',table,'-F',chain)
    for table,chain,args in firewall_rules(c,xs):
        ipt('-t',table,'-A',chain,*args)
    for table,chain,base in CHAINS:
        ensure_rule(table,base,['-m','comment','--comment','icmp-tunnel-owned','-j',chain],position=1)

def firewall_stop():
    for table,chain,base in CHAINS:
        args=['-m','comment','--comment','icmp-tunnel-owned','-j',chain]
        while not ipt('-t',table,'-C',base,*args,check=False).returncode:
            ipt('-t',table,'-D',base,*args)
        if not ipt('-t',table,'-S',chain,check=False).returncode:
            ipt('-t',table,'-F',chain)
            ipt('-t',table,'-X',chain)

def firewall_healthy(state):
    for table,chain,base in CHAINS:
        if ipt('-t',table,'-C',base,'-m','comment','--comment','icmp-tunnel-owned','-j',chain,check=False).returncode:
            return False
    return all(not ipt('-t',table,'-C',chain,*args,check=False).returncode
               for table,chain,args in firewall_rules(state['config'],state['carriers']))


def nat_port_conflict(text,port):
    """Conservative conflict detection, including custom NAT chains/multiport ranges."""
    for line in text.splitlines():
        if not line.startswith('-A '):
            continue
        args=shlex.split(line)
        if '-j' not in args or args[args.index('-j')+1] not in ('DNAT','REDIRECT'):
            continue
        selectors=[args[i+1] for i,a in enumerate(args[:-1]) if a in ('--dport','--dports','--destination-port','--destination-ports')]
        if not selectors:
            return True
        for selector in selectors:
            for part in selector.split(','):
                ends=part.split(':')
                try:
                    if len(ends)==1 and int(ends[0])==port:
                        return True
                    if len(ends)==2 and int(ends[0] or 0)<=port<=int(ends[1] or 65535):
                        return True
                except ValueError:
                    return True
    return False

def firewall_audit(port=9094):
    """Audit system firewall for conflicts on port and check for experimental remnants."""
    cbtun = False
    cbgre2 = False
    conflicts = []
    if shutil.which('nft'):
        try:
            out = run(['nft', 'list', 'tables'], check=False).stdout
            if 'cbtun' in out:
                cbtun = True
                conflicts.append("Rogue nftables table 'cbtun' detected")
            if 'cbgre2' in out:
                cbgre2 = True
                conflicts.append("Rogue nftables table 'cbgre2' detected")
        except Exception:
            pass
    if shutil.which('iptables-save'):
        try:
            nat = run(['iptables-save', '-t', 'nat'], check=False).stdout
            for line in nat.splitlines():
                if 'cbtun' in line:
                    cbtun = True
                if 'cbgre2' in line:
                    cbgre2 = True
                if not line.startswith('-A '):
                    continue
                if any(x in line for x in ('IT2_DNAT', 'IT2_SNAT', 'icmp-tunnel-owned')):
                    continue
                args = shlex.split(line)
                if '-j' in args and args[args.index('-j')+1] in ('DNAT', 'REDIRECT'):
                    selectors = [args[i+1] for i, a in enumerate(args[:-1]) if a in ('--dport', '--dports', '--destination-port', '--destination-ports')]
                    for selector in selectors:
                        for part in selector.split(','):
                            ends = part.split(':')
                            try:
                                if (len(ends) == 1 and int(ends[0]) == port) or (len(ends) == 2 and int(ends[0] or 0) <= port <= int(ends[1] or 65535)):
                                    conflicts.append(f"Conflicting iptables NAT rule on port {port}: {line}")
                            except ValueError:
                                pass
        except Exception:
            pass
    return {
        'cbtun': 'FOUND' if cbtun else 'NONE',
        'cbgre2': 'FOUND' if cbgre2 else 'NONE',
        'conflicts': conflicts,
        'passed': len(conflicts) == 0 and not cbtun and not cbgre2
    }
