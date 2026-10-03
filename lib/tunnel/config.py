"""Strict public configuration, pairing validation, and carrier allocation."""
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path

class Error(Exception):
    """An actionable, safe-to-display operational error."""

DEFAULTS = dict(ROLE='foreign', FOREIGN_PUBLIC_IP='',
                PRIMARY_FOREIGN_ENDPOINT='', SECONDARY_FOREIGN_ENDPOINT='', FOREIGN_ENDPOINTS='',
                AUTO_FAILOVER='yes', AUTO_FAILBACK='no',
                FAILURE_THRESHOLD=3, RECOVERY_THRESHOLD=5, FAILOVER_COOLDOWN=300,
                PUBLIC_LISTEN_PORT=9094, APPLICATION_PORT=9094, CARRIER_COUNT=3, WIREGUARD_MTU=1360,
                CARRIER_PORT_BASE=42094, WG_PORT_BASE=51894, LOCAL_PORT_BASE=53894,
                TUNNEL_NETWORK='10.203.0.0/24', NETWORK_INTERFACE='', CPU_AFFINITY='yes',
                SELF_HEAL='no', HEALTH_FAILURES=3, HEALTH_COOLDOWN=300,
                HANDSHAKE_MAX_AGE=180, PEER_FILE='')
PAIR_FIELDS = {'schema', 'config', 'carriers'}
CARRIER_FIELDS = {'name', 'iran_ip', 'foreign_ip', 'raw_port', 'wg_port', 'local_port',
                  'private', 'public', 'peer_public', 'psk', 'raw_secret'}

def private_file(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise Error('Secret input must be a regular file, not a symlink.')
    if stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise Error('Secret input is readable by others; run chmod 600 on it.')
    if p.stat().st_uid not in (0, int(os.environ.get('SUDO_UID', os.getuid()))):
        raise Error('Secret input must belong to root or the invoking user.')
    return p

def read_env(path):
    result = {}
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as e:
        raise Error(f'Cannot read configuration: {e.strerror}') from None
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in DEFAULTS or key in result:
            raise Error(f'Invalid/duplicate configuration key on line {n}.')
        if any(x in value for x in ('\n', '\r', '\x00', '$', '`', '"', "'", ';')):
            raise Error(f'Configuration must be literal unquoted data (line {n}).')
        result[key] = value
    return result

def ipv4(value, public=False):
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise Error('An IPv4 address is required.') from None
    if public and not ip.is_global:
        raise Error('FOREIGN_PUBLIC_IP must be an externally routable IPv4 address.')
    return str(ip)

def validate(values, require_public=True):
    if set(values) - set(DEFAULTS):
        raise Error('Unknown configuration fields.')
    c = {**DEFAULTS, **values}
    if c['ROLE'] not in ('foreign', 'iran'):
        raise Error('ROLE must be foreign or iran.')
    limits = dict(PUBLIC_LISTEN_PORT=(1,65535), APPLICATION_PORT=(1,65535),
                  CARRIER_COUNT=(1,8), WIREGUARD_MTU=(576,1420),
                  CARRIER_PORT_BASE=(1024,65528), WG_PORT_BASE=(1024,65528),
                  LOCAL_PORT_BASE=(1024,65528), HEALTH_FAILURES=(2,20),
                  HEALTH_COOLDOWN=(60,86400), HANDSHAKE_MAX_AGE=(120,86400),
                  FAILURE_THRESHOLD=(2,20), RECOVERY_THRESHOLD=(2,20),
                  FAILOVER_COOLDOWN=(60,86400))
    for k, (lo, hi) in limits.items():
        if isinstance(c[k], bool) or not re.fullmatch(r'[0-9]+', str(c[k])):
            raise Error(f'{k} must be an integer.')
        c[k] = int(c[k])
        if not lo <= c[k] <= hi:
            raise Error(f'{k} is out of range ({lo}..{hi}).')
    for k in ('CPU_AFFINITY','SELF_HEAL','AUTO_FAILOVER','AUTO_FAILBACK'):
        if c[k] not in ('yes','no'):
            raise Error(f'{k} must be yes or no.')
    if not isinstance(c['NETWORK_INTERFACE'], str) or (c['NETWORK_INTERFACE'] and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', c['NETWORK_INTERFACE'])):
        raise Error('Invalid network interface name.')
    for k in ('PEER_FILE','FOREIGN_PUBLIC_IP','TUNNEL_NETWORK','PRIMARY_FOREIGN_ENDPOINT','SECONDARY_FOREIGN_ENDPOINT','FOREIGN_ENDPOINTS'):
        if not isinstance(c[k], str):
            raise Error(f'{k} must be text.')
    try:
        net = ipaddress.IPv4Network(c['TUNNEL_NETWORK'], strict=True)
    except ValueError:
        raise Error('TUNNEL_NETWORK must be an aligned IPv4 CIDR.') from None
    private = any(net.subnet_of(ipaddress.IPv4Network(n)) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
    if not private or net.prefixlen > 30 or net.num_addresses < c['CARRIER_COUNT'] * 4:
        raise Error('TUNNEL_NETWORK must be RFC1918 space with one /30 per carrier.')
    c['TUNNEL_NETWORK'] = str(net)
    ports = [c[k]+i for k in ('CARRIER_PORT_BASE','WG_PORT_BASE','LOCAL_PORT_BASE') for i in range(c['CARRIER_COUNT'])]
    ports += [c['WG_PORT_BASE']+1000+i for i in range(c['CARRIER_COUNT'])]
    if max(ports) > 65535:
        raise Error('WireGuard Iran listen ports exceed 65535 (WG_PORT_BASE + 1000).')
    if len(set(ports)) != len(ports) or c['PUBLIC_LISTEN_PORT'] in ports or c['APPLICATION_PORT'] in ports:
        raise Error('Carrier, WireGuard, loopback and application ports must not overlap.')

    # Endpoint and multi-endpoint failover resolution
    endpoints = []
    if c['FOREIGN_ENDPOINTS'] and (not c['FOREIGN_PUBLIC_IP'] or c['FOREIGN_PUBLIC_IP'] == c['FOREIGN_ENDPOINTS'].split()[0]):
        raw_eps = [x.strip() for x in re.split(r'[,\s]+', c['FOREIGN_ENDPOINTS']) if x.strip()]
        endpoints = [ipv4(x, public=require_public) for x in raw_eps]
        if not endpoints:
            raise Error('FOREIGN_ENDPOINTS must contain at least one valid IPv4 address.')
    else:
        if c['FOREIGN_PUBLIC_IP']:
            endpoints.append(ipv4(c['FOREIGN_PUBLIC_IP'], public=require_public))
        elif c['PRIMARY_FOREIGN_ENDPOINT']:
            endpoints.append(ipv4(c['PRIMARY_FOREIGN_ENDPOINT'], public=require_public))
        if c['SECONDARY_FOREIGN_ENDPOINT']:
            sec = ipv4(c['SECONDARY_FOREIGN_ENDPOINT'], public=require_public)
            if sec not in endpoints:
                endpoints.append(sec)

    if endpoints:
        c['FOREIGN_ENDPOINTS'] = ' '.join(endpoints)
        c['FOREIGN_PUBLIC_IP'] = endpoints[0]
        c['PRIMARY_FOREIGN_ENDPOINT'] = endpoints[0]
        if len(endpoints) > 1 and not c['SECONDARY_FOREIGN_ENDPOINT']:
            c['SECONDARY_FOREIGN_ENDPOINT'] = endpoints[1]
    elif c['FOREIGN_PUBLIC_IP']:
        c['FOREIGN_PUBLIC_IP'] = ipv4(c['FOREIGN_PUBLIC_IP'], public=require_public)
        c['PRIMARY_FOREIGN_ENDPOINT'] = c['FOREIGN_PUBLIC_IP']
        c['FOREIGN_ENDPOINTS'] = c['FOREIGN_PUBLIC_IP']
    elif require_public:
        raise Error('Set FOREIGN_PUBLIC_IP to the reachable Foreign server IPv4 address.')
    return c

def layout(c):
    start = int(ipaddress.IPv4Network(c['TUNNEL_NETWORK']).network_address)
    return [dict(name=f'wg{9094+i}', iran_ip=str(ipaddress.IPv4Address(start+4*i+1)),
                 foreign_ip=str(ipaddress.IPv4Address(start+4*i+2)),
                 raw_port=c['CARRIER_PORT_BASE']+i, wg_port=c['WG_PORT_BASE']+i,
                 local_port=c['LOCAL_PORT_BASE']+i) for i in range(c['CARRIER_COUNT'])]

def cpu_mapping(count, cpus):
    cpus = sorted(set(cpus))
    if not cpus:
        raise Error('No usable CPUs detected.')
    return [cpus[i % len(cpus)] for i in range(count)]

def supported_os(osinfo):
    allowed = {'ubuntu': {'22.04','24.04','26.04'}, 'debian': {'12','13'}}
    if osinfo.get('VERSION_ID') not in allowed.get(osinfo.get('ID'), set()):
        raise Error('Supported: Ubuntu 22.04/24.04/26.04 LTS; Debian 12/13. Unsupported distribution: stopped.')

def wg_generate(kind='genkey'):
    return subprocess.check_output(['wg', kind], text=True).strip()

def public_key(key):
    return subprocess.check_output(['wg','pubkey'], input=key+'\n', text=True).strip()

def generate(c):
    foreign, iran = [], []
    for base in layout(c):
        fk, ik, psk = wg_generate(), wg_generate(), wg_generate('genpsk')
        fp, ip = public_key(fk), public_key(ik)
        shared = dict(psk=psk, raw_secret=os.urandom(32).hex())
        foreign.append({**base, **shared, 'private':fk, 'public':fp, 'peer_public':ip})
        iran.append({**base, **shared, 'private':ik, 'public':ip, 'peer_public':fp})
    return foreign, {'schema':1,'config':{**c,'ROLE':'iran','PEER_FILE':'','NETWORK_INTERFACE':''}, 'carriers':iran}

def validate_carriers(c, carriers):
    if not isinstance(carriers, list) or len(carriers) != c['CARRIER_COUNT']:
        raise Error('Invalid carrier count in secret state.')
    for b, x in zip(layout(c), carriers):
        if not isinstance(x, dict) or set(x) != CARRIER_FIELDS or any(x[k] != v for k,v in b.items()):
            raise Error('Invalid carrier layout in secret state.')
        for k in ('private','public','peer_public','psk'):
            if not isinstance(x[k], str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}=',x[k]):
                raise Error('Invalid key encoding in secret state.')
        if not isinstance(x['raw_secret'],str) or not re.fullmatch(r'[0-9a-f]{64}',x['raw_secret']):
            raise Error('Invalid carrier secret encoding.')
    for k in ('private','public','peer_public','psk','raw_secret'):
        if len({x[k] for x in carriers}) != len(carriers):
            raise Error('Carriers must have independent identities and secrets.')

def load_pair(path):
    try:
        p = private_file(path)
        if p.stat().st_size > 65536:
            raise Error('Pairing file is too large.')
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        raise Error('Cannot read valid pairing JSON.') from None
    if not isinstance(data, dict) or set(data) != PAIR_FIELDS or data['schema'] != 1:
        raise Error('Unsupported pairing schema.')
    c = validate(data['config'])
    if c['ROLE'] != 'iran':
        raise Error('Pairing bundle must describe the Iran role.')
    validate_carriers(c, data['carriers'])
    return c, data['carriers']

def write_json(path, data):
    """Atomic root-only JSON, on the same filesystem as its destination."""
    import tempfile
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.icmp-', dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(data,f,indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp,0o600)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
