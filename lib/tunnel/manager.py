"""Installation transactions and the public management CLI."""
import argparse
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import time
from . import host
from .config import (Error, DEFAULTS, generate, layout, load_pair, private_file,
                     public_key, read_env, validate, validate_carriers, write_json)
from .render import CHAINS, SYSCTL, firewall_rules, udp2raw, units, wireguard

ROOT=Path(__file__).resolve().parents[2]
STATE=host.ETC/'state.json'
PAIR=host.ETC/'peer.json'
MARKER='icmp-tunnel-managed-v2'

def version():
    return (ROOT/'VERSION').read_text().strip()

def require_root():
    if os.geteuid()!=0:
        raise Error('Run with sudo/root. No production server access is needed.')

def load_state():
    try:
        data=json.loads(private_file(STATE).read_text())
        if data.get('owner')!=MARKER or data.get('schema')!=1:
            raise Error('Unrecognized installation ownership/schema.')
        c=data['config']
        public={k:c[k] for k in DEFAULTS}
        validate(public)
        validate_carriers(public,data['carriers'])
        if not isinstance(c.get('LOCAL_IP'),str) or not isinstance(c.get('PHYSICAL_ROUTE'),dict):
            raise Error('Invalid recorded network state.')
        ipaddress.IPv4Address(c['LOCAL_IP'])
        if set(data['original_sysctl'])!=set(SYSCTL):
            raise Error('Invalid saved sysctl state.')
        for v in data['original_sysctl'].values():
            if not isinstance(v,str) or '\n' in v:
                raise Error('Invalid saved sysctl value.')
        return data
    except (OSError,ValueError,KeyError,TypeError):
        raise Error('No valid installation found; inspect /etc/icmp-tunnel without sharing its secrets.') from None

def lock(firewall=False):
    p=Path('/run/lock/icmp-tunnel-firewall.lock' if firewall else '/run/lock/icmp-tunnel.lock')
    fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    if os.fstat(fd).st_uid!=0:
        os.close(fd)
        raise Error('Management lock must be root-owned.')
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Error('Another installation or management operation is running; try again later.') from None
    return fd

def secure_dir(p):
    p.mkdir(parents=True,exist_ok=True,mode=0o700)
    if p.is_symlink() or p.stat().st_uid!=0:
        raise Error(f'{p} must be a root-owned directory, not a symlink.')
    p.chmod(0o700)

def write_text(p,text,mode=0o600):
    p=Path(p)
    fd,tmp=tempfile.mkstemp(prefix='.icmp-',dir=p.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(text)
        os.chmod(tmp,mode)
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def safe_destination(path):
    p=Path(path).absolute()
    if p.exists() or p.is_symlink():
        raise Error('Output already exists; choose a new filename.')
    if not p.parent.is_dir() or p.parent.is_symlink() or p.parent.stat().st_uid!=0 or p.parent.stat().st_mode & 0o022:
        raise Error('Output directory must be root-owned and not writable by group/others (e.g. /root).')
    if any((parent/'.git').exists() for parent in (p.parent,*p.parent.parents)):
        raise Error('Secrets/backups must be exported outside Git working trees.')
    return p

def export_peer(path='/root/icmp-tunnel-peer.json'):
    s=load_state()
    if s['config']['ROLE']!='foreign' or not PAIR.exists():
        raise Error('Peer export is available on the original Foreign installation.')
    p=safe_destination(path)
    write_json(p,json.loads(private_file(PAIR).read_text()))
    print(f'SECRET pairing bundle: {p} (0600). Transfer using SSH/SCP; never commit or attach it to an issue.')

def backup(path=None):
    s=load_state()
    if path is None:
        secure_dir(host.VAR/'backups')
        path=host.VAR/'backups'/f'tunnel-{time.time_ns()}.tar.gz'
    p=safe_destination(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as out, tarfile.open(fileobj=out,mode='w:gz') as t:
            for name,data in [('state.json',s), *([('peer.json',json.loads(private_file(PAIR).read_text()))] if PAIR.exists() else [])]:
                b=json.dumps(data).encode()
                info=tarfile.TarInfo(name); info.size=len(b); info.mode=0o600
                t.addfile(info,io.BytesIO(b))
    except Exception:
        p.unlink(missing_ok=True)
        raise
    print(f'SECRET backup: {p} (0600). Keep offline, outside Git; it contains private keys and pairing material.')
    return p

def source_copy(source, destination):
    destination.mkdir(mode=0o755)
    for name in ('VERSION','lib','scripts','install.sh','uninstall.sh'):
        src=source/name
        if src.is_dir():
            shutil.copytree(src,destination/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        else:
            shutil.copy2(src,destination/name)
    for p in destination.rglob('*'):
        if p.is_symlink():
            raise Error('Source distribution must not contain symlinks.')
        p.chmod(0o755 if p.is_dir() or p.suffix=='.sh' else 0o644)
    (destination/'bin').mkdir(mode=0o755)

def build_binary(destination):
    print('Building pinned udp2raw source (production revision).')
    with tempfile.TemporaryDirectory(prefix='icmp-tunnel-build-') as tmp:
        host.run(['git','clone',host.UPSTREAM,tmp],timeout=600)
        host.run(['git','-C',tmp,'checkout','--detach',host.UPSTREAM_REV])
        if host.run(['git','-C',tmp,'rev-parse','HEAD']).stdout.strip()!=host.UPSTREAM_REV:
            raise Error('udp2raw revision verification failed.')
        host.run(['make','-C',tmp,'-j',str(min(len(os.sched_getaffinity(0)),3))],timeout=600)
        shutil.copy2(Path(tmp)/'udp2raw',destination/'bin/udp2raw')
        (destination/'bin/udp2raw').chmod(0o755)

def unit_names(s):
    return list(units(s['config'],s['carriers'],sorted(os.sched_getaffinity(0))))

def install_rendered(s):
    secure_dir(host.ETC/'wg'); secure_dir(host.ETC/'raw')
    c=s['config']
    for x in s['carriers']:
        write_text(host.ETC/'wg'/f'{x["name"]}.conf',wireguard(c,x))
        write_text(host.ETC/'raw'/f'{x["name"]}.conf',udp2raw(c,x))
    for name,text in units(c,s['carriers'],sorted(os.sched_getaffinity(0))).items():
        write_text(host.UNITDIR/name,text,0o644)
    write_text(host.SYSFILE,'# Owned by ICMP Tunnel; original values recorded in state.json\n'+
               ''.join(f'{k} = {v}\n' for k,v in SYSCTL.items()),0o644)
    write_text(host.CLI,'#!/usr/bin/env bash\nset -Eeuo pipefail\numask 077\nexec /usr/bin/python3 /opt/icmp-tunnel/scripts/tunnelctl.py "$@"\n',0o755)
    host.run(['systemctl','daemon-reload'])

def apply_sysctl():
    host.run(['sysctl','-p',host.SYSFILE])

def restore_sysctl(s):
    for key,old in s['original_sysctl'].items():
        current=' '.join(host.run(['sysctl','-n',key],check=False).stdout.split())
        # Respect an administrator's intervening change.
        if current==SYSCTL[key]:
            host.run(['sysctl','-w',f'{key}={old}'],check=False)
    host.SYSFILE.unlink(missing_ok=True)

def start(s):
    host.run(['systemctl','enable','--now','icmp-tunnel-firewall.service'])
    for x in s['carriers']:
        for kind in ('raw','wg'):
            host.run(['systemctl','enable','--now',f'icmp-tunnel-{kind}-{x["name"]}.service'])
    for x in s['carriers']:
        for kind in ('raw','wg'):
            host.run(['systemctl','is-active','--quiet',f'icmp-tunnel-{kind}-{x["name"]}.service'])
        host.run(['ip','link','show','dev',x['name']])
    host.run(['systemctl','enable','--now','icmp-tunnel-health.timer'])

def stop(s):
    names=['icmp-tunnel-health.timer','icmp-tunnel-health.service']
    names += [f'icmp-tunnel-{kind}-{x["name"]}.service' for x in s['carriers'] for kind in ('wg','raw')]
    names += ['icmp-tunnel-firewall.service']
    for name in names:
        host.run(['systemctl','disable','--now',name],check=False)
    # If wg-quick failed to finish, remove only recorded project interfaces.
    for x in s['carriers']:
        host.run(['ip','link','delete','dev',x['name']],check=False)
    host.firewall_stop()

def cleanup(s, remove_secrets=True):
    stop(s)
    for name in unit_names(s):
        (host.UNITDIR/name).unlink(missing_ok=True)
    restore_sysctl(s)
    host.CLI.unlink(missing_ok=True)
    shutil.rmtree(host.APP,ignore_errors=True)
    if remove_secrets:
        shutil.rmtree(host.ETC,ignore_errors=True)
    # Backups are never removed implicitly.
    if host.VAR.exists():
        for name in ('health.json','transaction.json'):
            (host.VAR/name).unlink(missing_ok=True)
        remaining=set(p.name for p in host.VAR.iterdir())
        if remaining <= {'owner.json'}:
            (host.VAR/'owner.json').unlink(missing_ok=True)
            host.VAR.rmdir()
    host.run(['systemctl','daemon-reload'])

def install(c, pair=None):
    if STATE.exists():
        load_state()
        raise Error('Already installed. Use tunnelctl repair or install.sh --upgrade; keys will not be regenerated.')
    require_root()
    cpus=host.preflight(c)
    host.install_packages()
    # Repeat checks after package installation, before claiming project resources.
    host.preflight(c)
    if pair is None:
        carriers,bundle=generate({k:c[k] for k in DEFAULTS})
    else:
        carriers,bundle=pair,None
        for x in carriers:
            if public_key(x['private'])!=x['public']:
                raise Error('Pairing private/public key mismatch.')
    s=dict(owner=MARKER,schema=1,version=version(),config=c,carriers=carriers,
           original_sysctl={k:host.run(['sysctl','-n',k]).stdout.strip() for k in SYSCTL})
    # Build/copy code before any runtime resource is created.
    with tempfile.TemporaryDirectory(prefix='icmp-tunnel-stage-',dir=host.APP.parent) as tmp:
        stage=Path(tmp)/'app'
        source_copy(ROOT,stage)
        build_binary(stage)
        # Commit the claim and original state first, allowing interrupted-install recovery.
        try:
            secure_dir(host.ETC); secure_dir(host.VAR)
            write_json(host.VAR/'owner.json',{'owner':MARKER})
            write_json(STATE,s)
            write_json(host.VAR/'transaction.json',{'operation':'install','phase':'applying'})
            os.replace(stage,host.APP)
            if bundle:
                write_json(PAIR,bundle)
            install_rendered(s)
            apply_sysctl()
            start(s)
            (host.VAR/'transaction.json').unlink()
        except BaseException:
            print('Installation failed; rolling back project resources and unchanged original sysctl values.',file=sys.stderr)
            try:
                cleanup(s)
            except Exception:
                print('Rollback incomplete. Run this checkout: sudo ./install.sh --uninstall. Original state remains in /etc/icmp-tunnel.',file=sys.stderr)
            raise
    print(f'Installed {version()} ({c["ROLE"]}), {len(cpus)} usable CPUs, {len(carriers)} carriers.')
    print('The Foreign application must listen on every Foreign carrier address (or 0.0.0.0), TCP and UDP, on APPLICATION_PORT.')
    if bundle:
        print('Next: sudo tunnelctl export-peer /root/icmp-tunnel-peer.json; securely transfer that SECRET file to Iran.')
    else:
        print(f'Iran public relay: TCP+UDP :{c["PUBLIC_LISTEN_PORT"]}. Run sudo tunnelctl health after both endpoints are up.')

def restart_carrier(s,index):
    if not 1<=index<=len(s['carriers']):
        raise Error('Carrier index is out of range.')
    x=s['carriers'][index-1]
    for kind in ('raw','wg'):
        host.run(['systemctl','restart',f'icmp-tunnel-{kind}-{x["name"]}.service'])

def status(s):
    c=s['config']
    print(f'Version: {version()} | installed state: {s["version"]} | role: {c["ROLE"]} | carriers: {len(s["carriers"])}')
    print(f'Public relay: TCP+UDP :{c["PUBLIC_LISTEN_PORT"]} | Foreign application: :{c["APPLICATION_PORT"]} | MTU: {c["WIREGUARD_MTU"]}')
    print('BBR: '+host.run(['sysctl','-n','net.ipv4.tcp_congestion_control'],check=False).stdout.strip())
    for i,x in enumerate(s['carriers'],1):
        print(f'Carrier {i}: {x["name"]}')
        for kind in ('wg','raw'):
            p=host.run(['systemctl','is-active',f'icmp-tunnel-{kind}-{x["name"]}.service'],check=False)
            print(f'  {kind}: {p.stdout.strip() or "unknown"}')
        for field in ('latest-handshakes','transfer'):
            out=host.run(['wg','show',x['name'],field],check=False).stdout.splitlines()
            # wg field selectors explicitly exclude private/PSK material.
            print(f'  {field}: '+', '.join(' '.join(row.split()[1:]) for row in out))
        p=host.run(['ip','-j','link','show','dev',x['name']],check=False)
        if p.returncode==0:
            link=json.loads(p.stdout)[0]
            print('  WireGuard interface: '+('UP' if 'UP' in link.get('flags',[]) else 'DOWN')+' | actual MTU: '+str(link['mtu']))
        else:
            print('  WireGuard interface: DOWN (missing)')
    for unit in ('icmp-tunnel-firewall.service','icmp-tunnel-health.timer'):
        print(unit+': '+host.run(['systemctl','is-active',unit],check=False).stdout.strip())
    if c['ROLE'] == 'iran':
        endpoints = c.get('FOREIGN_ENDPOINTS', '').split()
        if endpoints:
            active_ep = c.get('FOREIGN_PUBLIC_IP', '')
            print(f'Active Foreign endpoint: {active_ep}')
            tags = []
            for ep in endpoints:
                tag = 'primary' if ep == c.get('PRIMARY_FOREIGN_ENDPOINT') else ('secondary' if ep == c.get('SECONDARY_FOREIGN_ENDPOINT') else 'candidate')
                marker = ' [ACTIVE]' if ep == active_ep else ''
                tags.append(f'{ep} ({tag}){marker}')
            print('Configured Foreign endpoints: ' + ', '.join(tags))
            print(f'Auto failover: {c.get("AUTO_FAILOVER", "yes")} | Auto failback: {c.get("AUTO_FAILBACK", "no")} | Cooldown: {c.get("FAILOVER_COOLDOWN", 300)}s')
    audit = host.firewall_audit(c['PUBLIC_LISTEN_PORT'])
    print(f'Firewall conflict status: {"PASS" if audit["passed"] else "FAIL"} | cbtun: {audit["cbtun"]} | cbgre2: {audit["cbgre2"]}')

def sysctl_healthy():
    return all(' '.join(host.run(['sysctl','-n',k],check=False).stdout.split())==v for k,v in SYSCTL.items())

def probe(s,x):
    reasons=[]
    for kind in ('wg','raw'):
        if host.run(['systemctl','is-active',f'icmp-tunnel-{kind}-{x["name"]}.service'],check=False).returncode:
            reasons.append(kind+' service down')
    link=host.run(['ip','-j','link','show','dev',x['name']],check=False)
    if link.returncode:
        reasons.append('interface missing')
    elif json.loads(link.stdout)[0]['mtu']!=s['config']['WIREGUARD_MTU']:
        reasons.append('MTU mismatch')
    peer=x['foreign_ip'] if s['config']['ROLE']=='iran' else x['iran_ip']
    route=host.run(['ip','-j','-4','route','get',peer],check=False)
    if route.returncode or json.loads(route.stdout)[0].get('dev')!=x['name']:
        reasons.append('peer routing failure')
    if host.run(['ping','-n','-q','-I',x['name'],'-c','1','-W','2',peer],check=False,timeout=5).returncode:
        reasons.append('peer probe failed (ICMP or peer unavailable)')
    rows=host.run(['wg','show',x['name'],'latest-handshakes'],check=False).stdout.splitlines()
    stamps=[int(r.split()[-1]) for r in rows if r.split()[-1].isdigit()]
    if not stamps or not max(stamps) or time.time()-max(stamps)>s['config']['HANDSHAKE_MAX_AGE']:
        reasons.append('handshake absent/stale')
    return reasons

def health(s,recover=False):
    secure_dir(host.VAR)
    path=host.VAR/'health.json'
    history=json.loads(path.read_text()) if path.exists() else {}
    failures=False
    global_good=host.firewall_healthy(s) and sysctl_healthy()
    if not global_good:
        print('FAIL: firewall or sysctl differs; use tunnelctl repair. Carrier recovery withheld.')
        failures=True
    recovered=False
    for i,x in enumerate(s['carriers'],1):
        reasons=probe(s,x)
        print(f'{x["name"]}: '+('; '.join(reasons) if reasons else 'PASS'))
        h=history.setdefault(x['name'],{'failures':0,'last_restart':0})
        h['failures']=h['failures']+1 if reasons else 0
        failures |= bool(reasons)
        if (reasons and recover and s['config']['SELF_HEAL']=='yes' and global_good and not recovered
                and h['failures']>=s['config']['HEALTH_FAILURES']
                and time.time()-h['last_restart']>=s['config']['HEALTH_COOLDOWN']
                and len([t for t in h.get('attempts',[]) if time.time()-t<3600])<3):
            # Record cooldown before restart, including failed restart attempts.
            h.update(last_restart=time.time(),failures=0,attempts=[t for t in h.get('attempts',[]) if time.time()-t<3600]+[time.time()])
            write_json(path,history)
            recovered=True
            try:
                restart_carrier(s,i)
                after=probe(s,x)
                print(f'{x["name"]}: recovery '+('still failing: '+'; '.join(after) if after else 'PASS'))
            except Error as e:
                print(f'{x["name"]}: recovery failed: {e}')
    write_json(path,history)
    return 1 if failures else 0

def redact(text,s):
    """Redact all actual credentials plus recognizable generic credential forms."""
    import re
    secrets=[x[k] for x in s['carriers'] for k in ('private','psk','raw_secret')]
    if PAIR.exists():
        try:
            secrets += [x['private'] for x in json.loads(private_file(PAIR).read_text())['carriers']]
        except (Error,ValueError,KeyError):
            return '[log omitted: pairing redaction unavailable]'
    for value in sorted(secrets,key=len,reverse=True):
        text=text.replace(value,'[REDACTED]')
    text=re.sub(r'(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',text)
    text=re.sub(r"(?im)((?:privatekey|presharedkey|password|passwd|token|secret|cookie|authorization|api[_-]?key)\b[\"']?\s*[:=]\s*).*$",r'\1[REDACTED]',text)
    text=re.sub(r"(?<!\S)(-k\s+)(?:\"[^\"]*\"|'[^']*'|\S+)",r'\1[REDACTED]',text)
    text=re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b','[REDACTED]',text)
    return text

def logs(s,lines=60):
    args=['journalctl','--no-pager','-n',str(lines),'--output=short-iso']
    for name in unit_names(s):
        if name.endswith('.service'):
            args+=['-u',name]
    print(redact(host.run(args,check=False).stdout,s))

def diagnostics(s):
    print('NON-SECRET diagnostics; includes IP addresses/topology. Review before sharing.')
    print(host.os_info().get('PRETTY_NAME'))
    print('Kernel: '+host.run(['uname','-r']).stdout.strip())
    print('Usable CPU IDs: '+str(sorted(os.sched_getaffinity(0))))
    status(s)
    for x in s['carriers']:
        for args in (['ip','-s','link','show','dev',x['name']],['ip','-4','route','show','dev',x['name']]):
            print(host.run(args,check=False).stdout)
    print('Outer physical route: '+host.run(['ip','-4','route','get',s['config']['FOREIGN_PUBLIC_IP']],check=False).stdout)
    for table,chain,_ in CHAINS:
        print(host.ipt('-t',table,'-S',chain,check=False).stdout)
    for k in SYSCTL:
        print(k+' = '+host.run(['sysctl','-n',k],check=False).stdout.strip())
    logs(s,40)

def repair(s):
    if (host.VAR/'transaction.json').exists():
        raise Error('An interrupted transaction exists. Inspect it and run uninstall, or restore the external backup; do not overwrite it.')
    c=s['config']
    host.preflight(c,existing=True)
    backup()
    # Repair takes a full local snapshot so partial writes can be reversed.
    transactional_update(s, ROOT, rebuild=False)

def transactional_update(s,source,rebuild=False,pair_bundle=None):
    """Keep configuration and executable snapshot outside source Git directories."""
    secure_dir(host.VAR)
    if (host.VAR/'transaction.json').exists():
        raise Error('An interrupted transaction exists; resolve it before changing the installation.')
    with tempfile.TemporaryDirectory(prefix='update-',dir=host.VAR) as tmp:
        snapshot=Path(tmp)
        shutil.copytree(host.ETC,snapshot/'etc')
        shutil.copytree(host.APP,snapshot/'app')
        old_sysfile=host.SYSFILE.read_text()
        old_units={n:(host.UNITDIR/n).read_text() for n in unit_names(load_state())}
        original=load_state()
        write_json(host.VAR/'transaction.json',{'operation':'update','snapshot':str(snapshot),'phase':'applying'})
        try:
            stop(original)
            if rebuild:
                stage=snapshot/'new-app'
                source_copy(source,stage)
                shutil.copy2(snapshot/'app/bin/udp2raw',stage/'bin/udp2raw')
                shutil.rmtree(host.APP)
                os.replace(stage,host.APP)
            write_json(STATE,s)
            if pair_bundle is not None:
                write_json(PAIR,pair_bundle)
            if rebuild:
                # Use the incoming release's renderer, not the old process's templates.
                host.run(['python3',host.APP/'scripts/tunnelctl.py','_render'])
            else:
                install_rendered(s)
            apply_sysctl()
            start(s)
        except BaseException:
            print('Update failed; restoring saved executable/configuration snapshot.',file=sys.stderr)
            try:
                stop(s)
                shutil.rmtree(host.ETC); shutil.copytree(snapshot/'etc',host.ETC)
                shutil.rmtree(host.APP); shutil.copytree(snapshot/'app',host.APP)
                write_text(host.SYSFILE,old_sysfile,0o644)
                for n,text in old_units.items():
                    write_text(host.UNITDIR/n,text,0o644)
                host.run(['systemctl','daemon-reload'])
                apply_sysctl(); start(original)
            except BaseException:
                # Preserve snapshot even if rollback fails or the process is interrupted.
                retained=host.VAR/f'failed-update-{time.time_ns()}'
                shutil.copytree(snapshot,retained)
                write_json(host.VAR/'transaction.json',{'operation':'failed-update','snapshot':str(retained)})
                print(f'Rollback failed. Root-only snapshot retained at {retained}.',file=sys.stderr)
                raise
            (host.VAR/'transaction.json').unlink(missing_ok=True)
            raise
        (host.VAR/'transaction.json').unlink(missing_ok=True)
    print('Update complete; generated keys and public settings preserved.')

def upgrade(s,source):
    source=Path(source).resolve()
    if source==host.APP:
        raise Error('Specify an updated checkout: tunnelctl upgrade --source /path/to/repository.')
    for name in ('VERSION','lib/tunnel/manager.py','scripts/tunnelctl.py','install.sh'):
        if not (source/name).is_file():
            raise Error('Upgrade source is not a complete installer checkout.')
    new_version=(source/'VERSION').read_text().strip()
    import re
    if not re.fullmatch(r'2\.\d+\.\d+',new_version):
        raise Error('Only compatible Release 2 upgrades are supported; major upgrades need a migration.')
    host.preflight(s['config'],existing=True)
    backup()
    updated={**s,'version':new_version}
    transactional_update(updated,source,rebuild=True)

def restore(s,path):
    p=private_file(path)
    if p.stat().st_size>1024*1024:
        raise Error('Backup too large.')
    try:
        with tarfile.open(p,'r:gz') as t:
            members=t.getmembers()
            if {m.name for m in members}-{'state.json','peer.json'} or len({m.name for m in members})!=len(members):
                raise Error('Unexpected/duplicate backup members.')
            if any(not m.isfile() or m.size>65536 for m in members):
                raise Error('Invalid backup members.')
            incoming=json.load(t.extractfile('state.json'))
            pair=json.load(t.extractfile('peer.json')) if 'peer.json' in t.getnames() else None
    except (OSError,ValueError,KeyError,tarfile.TarError):
        raise Error('Invalid backup archive; nothing extracted.') from None
    if incoming.get('owner')!=MARKER or incoming.get('schema')!=1:
        raise Error('Unrecognized backup schema.')
    incoming_c=validate({k:incoming['config'][k] for k in DEFAULTS})
    validate_carriers(incoming_c,incoming['carriers'])
    for k in DEFAULTS:
        if k not in ('PEER_FILE',) and incoming_c[k]!=s['config'][k]:
            raise Error('Restore requires the same role and public configuration. Configure/install the matching layout first.')
    for x in incoming['carriers']:
        if public_key(x['private'])!=x['public']:
            raise Error('Backup key mismatch.')
    # Pair backup is validated before any mutation. Never extract paths from tar.
    if incoming_c['ROLE']=='foreign' and pair is None:
        raise Error('Foreign backup must include its matching pairing bundle.')
    if pair is not None:
        if incoming_c['ROLE']!='foreign':
            raise Error('An Iran backup must not include a Foreign export bundle.')
        with tempfile.TemporaryDirectory(prefix='pair-validate-') as tmp:
            q=Path(tmp)/'pair.json'; write_json(q,pair)
            load_pair(q)
        for foreign,iran in zip(incoming['carriers'],pair['carriers']):
            if (foreign['public']!=iran['peer_public'] or foreign['peer_public']!=iran['public']
                    or foreign['psk']!=iran['psk'] or foreign['raw_secret']!=iran['raw_secret']):
                raise Error('Backup pairing material does not match the Foreign identities.')
    backup()
    updated={**s,'carriers':incoming['carriers']}
    transactional_update(updated,ROOT,pair_bundle=pair)
    print('Restore complete. Both endpoints must use matching pairing identities.')

def uninstall(s,delete_secrets=False,yes=False):
    if not yes and sys.stdin.isatty():
        if input('Remove this project installation? [y/N] ').lower()!='y':
            return
    elif not yes:
        raise Error('Non-interactive uninstall requires --yes. Secrets are backed up unless --delete-secrets is given.')
    if delete_secrets and not yes:
        if input('Delete generated secret configuration too? [y/N] ').lower()!='y':
            delete_secrets=False
    if not delete_secrets:
        backup()
    cleanup(s)
    print('Project removed. Distribution packages and secret backups retained. Unrelated services/firewall policies unchanged.')

def endpoint_list(s):
    c = s['config']
    active = c.get('FOREIGN_PUBLIC_IP', '')
    endpoints = c.get('FOREIGN_ENDPOINTS', '').split()
    print('Configured Foreign Endpoints:')
    for ep in endpoints:
        tag = 'primary' if ep == c.get('PRIMARY_FOREIGN_ENDPOINT') else ('secondary' if ep == c.get('SECONDARY_FOREIGN_ENDPOINT') else 'candidate')
        marker = ' [ACTIVE]' if ep == active else ''
        print(f'  {ep} ({tag}){marker}')

def endpoint_check(s):
    c = s['config']
    endpoints = c.get('FOREIGN_ENDPOINTS', '').split()
    print('Checking reachability of configured Foreign endpoints:')
    for ep in endpoints:
        p = host.run(['ping', '-n', '-q', '-c', '1', '-W', '2', ep], check=False, timeout=5)
        print(f'  {ep}: {"REACHABLE" if p.returncode == 0 else "UNREACHABLE"}')

def endpoint_switch(s, target):
    c = s['config']
    endpoints = c.get('FOREIGN_ENDPOINTS', '').split()
    if target.lower() == 'primary':
        target = c.get('PRIMARY_FOREIGN_ENDPOINT', endpoints[0] if endpoints else '')
    elif target.lower() == 'secondary':
        target = c.get('SECONDARY_FOREIGN_ENDPOINT', endpoints[1] if len(endpoints) > 1 else '')
    if not target or target not in endpoints:
        raise Error(f'Target {target} is not in configured FOREIGN_ENDPOINTS ({endpoints}).')
    print(f'Staged migration of carriers to Foreign endpoint {target}...')
    c['FOREIGN_PUBLIC_IP'] = target
    s['config'] = c
    for i, x in enumerate(s['carriers'], 1):
        raw_conf = host.ETC / 'raw' / f'{x["name"]}.conf'
        if raw_conf.exists():
            lines = raw_conf.read_text().splitlines()
            new_lines = []
            for line in lines:
                if line.startswith('-r '):
                    port = line.split(':')[1] if ':' in line else str(x['raw_port'])
                    new_lines.append(f'-r {target}:{port}')
                else:
                    new_lines.append(line)
            write_text(raw_conf, '\n'.join(new_lines) + '\n')
            restart_carrier(s, i)
            print(f'Carrier {x["name"]}: migrated to {target}.')
    write_json(STATE, s)
    print(f'Successfully switched active Foreign endpoint to {target}.')

def failover_control(s, action, value=None):
    c = s['config']
    if action == 'enable':
        c['AUTO_FAILOVER'] = 'yes'
        s['config'] = c
        write_json(STATE, s)
        print('Automated failover ENABLED.')
    elif action == 'disable':
        c['AUTO_FAILOVER'] = 'no'
        s['config'] = c
        write_json(STATE, s)
        print('Automated failover DISABLED.')
    elif action in ('auto-failback', 'autofailback'):
        val = 'yes' if value in ('on', 'enable', 'yes', 'true') else 'no'
        c['AUTO_FAILBACK'] = val
        s['config'] = c
        write_json(STATE, s)
        print(f'Auto failback set to {val}.')
    else:
        print(f'Auto Failover: {c.get("AUTO_FAILOVER", "yes")}')
        print(f'Auto Failback: {c.get("AUTO_FAILBACK", "no")}')
        print(f'Failure Threshold: {c.get("FAILURE_THRESHOLD", 3)}')
        print(f'Recovery Threshold: {c.get("RECOVERY_THRESHOLD", 5)}')
        print(f'Cooldown: {c.get("FAILOVER_COOLDOWN", 300)}s')

def failover_daemon(s):
    print('Starting ICMP Tunnel Failover Daemon...')
    failures = 0
    while True:
        try:
            s = load_state()
            c = s['config']
            endpoints = c.get('FOREIGN_ENDPOINTS', '').split()
            if len(endpoints) <= 1 or c.get('AUTO_FAILOVER') != 'yes':
                time.sleep(15)
                continue
            active = c.get('FOREIGN_PUBLIC_IP', endpoints[0])
            stale_count = 0
            for x in s['carriers']:
                out = host.run(['wg', 'show', x['name'], 'latest-handshakes'], check=False).stdout.splitlines()
                stamps = [int(r.split()[-1]) for r in out if r.split()[-1].isdigit()]
                if not stamps or not max(stamps) or time.time() - max(stamps) > int(c.get('HANDSHAKE_MAX_AGE', 180)):
                    stale_count += 1
            if stale_count == len(s['carriers']):
                failures += 1
                if failures >= int(c.get('FAILURE_THRESHOLD', 3)):
                    candidates = [ep for ep in endpoints if ep != active]
                    for cand in candidates:
                        p = host.run(['ping', '-n', '-q', '-c', '1', '-W', '2', cand], check=False, timeout=5)
                        if p.returncode == 0:
                            print(f'Active endpoint {active} failed ({failures} consecutive checks). Failing over to {cand}...')
                            endpoint_switch(s, cand)
                            failures = 0
                            time.sleep(int(c.get('FAILOVER_COOLDOWN', 300)))
                            break
            else:
                failures = 0
        except Exception as e:
            print(f'Error in failover cycle: {e}', file=sys.stderr)
        time.sleep(15)

def firewall_check(s):
    port = s['config']['PUBLIC_LISTEN_PORT']
    audit = host.firewall_audit(port)
    print('FIREWALL CONFLICT AUDIT:')
    print(f'  PUBLIC LISTEN PORT ({port}) OWNERSHIP: {"PASS" if audit["passed"] else "FAIL"}')
    print(f'  CBTUN REMNANTS: {audit["cbtun"]}')
    print(f'  CBGRE2 REMNANTS: {audit["cbgre2"]}')
    print(f'  FIREWALL CONFLICT DETECTION: {"PASS" if audit["passed"] else "FAIL"}')
    if audit['conflicts']:
        print('Conflicts found:')
        for c in audit['conflicts']:
            print(f'    - {c}')

def plan(c):
    print(f'DRY RUN: no keys generated, files written, services started, kernel modules loaded or network state changed. Version {version()}')
    print(json.dumps(c,indent=2))
    if c['CARRIER_COUNT']>len(os.sched_getaffinity(0)):
        print('WARNING: carriers will share usable CPU IDs.')
    for x in layout(c):
        print(f'Carrier: {x}')
    print('Would install packages: '+', '.join(host.PACKAGES))
    print('Would build pinned udp2raw: '+host.UPSTREAM_REV)
    print('Would generate independent WireGuard keys/PSKs and 256-bit random raw secrets (Foreign); import secret peer identities (Iran).')
    print('Would create: /etc/icmp-tunnel, /opt/icmp-tunnel, /var/lib/icmp-tunnel, /usr/local/bin/tunnelctl, dedicated units/sysctl.')
    print('Firewall rules (project chains only):')
    preview={**c,'NETWORK_INTERFACE':c['NETWORK_INTERFACE'] or '<physical-interface>'}
    for table,chain,args in firewall_rules(preview,layout(c)):
        print('iptables -t '+table+' -A '+chain+' '+' '.join(args))
    print('Would enable services/timer; global default route remains unchanged. Rollback removes project resources, conditionally restores sysctl.')

def detect_public_source():
    try:
        r=host.ip_json('route','get','1.1.1.1')[0]
        ip=ipaddress.IPv4Address(r.get('prefsrc',''))
        if ip.is_global and not r.get('dev','').startswith(('wg','tun','tap')):
            return str(ip)
    except (Error,ValueError,IndexError):
        pass
    return ''

def choose_install(args):
    vals=read_env(args.config) if args.config else {}
    if args.role:
        if 'ROLE' in vals and vals['ROLE']!=args.role:
            raise Error('--role and configuration ROLE disagree.')
        vals['ROLE']=args.role
    if args.peer:
        vals['PEER_FILE']=args.peer
    pair=None
    interactive=not any((args.role,args.config,args.peer,args.dry_run))
    if interactive:
        print('1. Install Foreign Server\n2. Install Iran Server\n3. Status\n4. Health Check\n5. Repair\n6. Upgrade\n7. Uninstall\n8. Exit')
        choice=input('Select: ').strip()
        command={'3':'status','4':'health','5':'repair','6':'upgrade','7':'uninstall','8':'exit'}.get(choice)
        if command:
            return command,None,None
        if choice not in ('1','2'):
            raise Error('Select a menu option from 1 to 8.')
        vals['ROLE']='foreign' if choice=='1' else 'iran'
        if vals['ROLE']=='foreign':
            detected=detect_public_source()
            if detected:
                print('Detected globally routable Foreign source IPv4: '+detected)
                vals['FOREIGN_PUBLIC_IP']=detected
            else:
                vals['FOREIGN_PUBLIC_IP']=input('Foreign externally reachable IPv4 (cannot safely detect through NAT): ').strip()
            value=input('Application TCP/UDP port [9094]: ').strip()
            if value:
                vals.update(APPLICATION_PORT=value,PUBLIC_LISTEN_PORT=value)
        else:
            vals['PEER_FILE']=input('Path to SECRET Foreign pairing JSON: ').strip()
    if vals.get('ROLE','foreign')=='iran' and vals.get('PEER_FILE'):
        peer_c,pair=load_pair(vals['PEER_FILE'])
        for k,v in vals.items():
            if k not in ('ROLE','PEER_FILE','NETWORK_INTERFACE','CPU_AFFINITY','SELF_HEAL','HEALTH_FAILURES','HEALTH_COOLDOWN','HANDSHAKE_MAX_AGE',
                         'PRIMARY_FOREIGN_ENDPOINT','SECONDARY_FOREIGN_ENDPOINT','FOREIGN_ENDPOINTS',
                         'AUTO_FAILOVER','AUTO_FAILBACK','FAILURE_THRESHOLD','RECOVERY_THRESHOLD','FAILOVER_COOLDOWN') and str(v)!=str(peer_c.get(k, '')):
                raise Error(f'{k} conflicts with paired Foreign configuration.')
        vals={**peer_c,**vals}
    elif vals.get('ROLE')=='iran' and not (args.dry_run and args.offline):
        raise Error('Iran installation requires --peer /path/to/secret-pair.json (or PEER_FILE in config).')
    if vals.get('ROLE','foreign')=='foreign' and not vals.get('FOREIGN_PUBLIC_IP') and not args.dry_run:
        vals['FOREIGN_PUBLIC_IP']=detect_public_source()
    return 'install',validate(vals,require_public=not (args.dry_run and args.offline)),pair

def main(argv=None):
    os.umask(0o077)
    parser=argparse.ArgumentParser(description='Portable multi-carrier WireGuard-over-ICMP tunnel installer/manager')
    parser.add_argument('command',nargs='?',default='status',choices=['install','status','health','repair','upgrade','uninstall','version','restart','restart-carrier','logs','diagnostics','config','export-peer','import-peer','backup','restore','_firewall','_render','endpoint','failover','firewall'])
    parser.add_argument('argument',nargs='?')
    parser.add_argument('extra',nargs='*')
    parser.add_argument('--role',choices=['foreign','iran'])
    parser.add_argument('--config')
    parser.add_argument('--peer')
    parser.add_argument('--source')
    parser.add_argument('--dry-run',action='store_true')
    parser.add_argument('--offline',action='store_true',help='configuration-only dry-run; host prerequisites are NOT verified')
    parser.add_argument('--upgrade',action='store_true')
    parser.add_argument('--uninstall',action='store_true')
    parser.add_argument('--recover',action='store_true')
    parser.add_argument('--yes',action='store_true')
    parser.add_argument('--delete-secrets',action='store_true')
    args=parser.parse_args(argv)
    fd=None
    try:
        if args.command=='version':
            print(version()); return 0
        if args.offline and not args.dry_run:
            raise Error('--offline is valid only with --dry-run.')
        if args.upgrade:
            args.command='upgrade'; args.source=args.source or str(ROOT)
        if args.uninstall:
            args.command='uninstall'
        if args.dry_run and args.command!='install':
            raise Error('--dry-run is supported for installation only.')
        if args.command=='import-peer':
            args.command='install'; args.role='iran'; args.peer=args.argument
        if args.command=='install':
            command,c,pair=choose_install(args)
            if command=='exit':
                return 0
            if command!='install':
                args.command=command
                if command=='upgrade':
                    args.source=str(ROOT)
            elif args.dry_run:
                if not args.offline:
                    require_root(); host.preflight(c)
                plan(c)
                if args.offline:
                    print('OFFLINE PREVIEW ONLY: OS/kernel/systemd/ports/firewall/connectivity preflight NOT verified.')
                return 0
            else:
                require_root(); fd=lock(); install(c,pair); return 0
        require_root(); fd=lock(firewall=args.command in ('_firewall','_render'))
        s=load_state()
        command=args.command
        if command=='status':
            status(s)
        elif command=='health':
            return health(s,args.recover)
        elif command=='repair':
            repair(s)
        elif command=='upgrade':
            upgrade(s,args.source or args.argument or str(ROOT))
        elif command=='uninstall':
            uninstall(s,args.delete_secrets,args.yes)
        elif command=='restart':
            for i in range(1,len(s['carriers'])+1):
                restart_carrier(s,i)
        elif command=='restart-carrier':
            if not args.argument or not args.argument.isdigit():
                raise Error('Usage: tunnelctl restart-carrier <1-based index>')
            restart_carrier(s,int(args.argument))
        elif command=='logs':
            logs(s)
        elif command=='diagnostics':
            diagnostics(s)
        elif command=='config':
            print(json.dumps({k:s['config'][k] for k in DEFAULTS if k!='PEER_FILE'},indent=2))
        elif command=='export-peer':
            export_peer(args.argument or '/root/icmp-tunnel-peer.json')
        elif command=='backup':
            backup(args.argument)
        elif command=='restore':
            if not args.argument:
                raise Error('Usage: tunnelctl restore /absolute/path/backup.tar.gz')
            restore(s,args.argument)
        elif command=='_render':
            install_rendered(s)
        elif command=='_firewall':
            # Invoked by systemd while install/update holds management lock.
            if args.argument=='start':
                host.firewall_start(s)
            elif args.argument=='stop':
                host.firewall_stop()
            else:
                raise Error('Internal firewall action must be start or stop.')
        elif command=='endpoint':
            sub = args.argument or 'list'
            if sub == 'list':
                endpoint_list(s)
            elif sub == 'check':
                endpoint_check(s)
            elif sub == 'switch':
                if not args.extra:
                    raise Error('Usage: tunnelctl endpoint switch <primary|secondary|IP>')
                endpoint_switch(s, args.extra[0])
            else:
                raise Error(f'Unknown endpoint command: {sub}. Valid: list, check, switch')
        elif command=='failover':
            sub = args.argument or 'status'
            if sub in ('enable', 'disable'):
                failover_control(s, sub)
            elif sub in ('auto-failback', 'autofailback'):
                val = args.extra[0] if args.extra else 'on'
                failover_control(s, 'auto-failback', val)
            elif sub == 'status':
                failover_control(s, 'status')
            elif sub == 'daemon':
                failover_daemon(s)
            else:
                raise Error(f'Unknown failover command: {sub}. Valid: enable, disable, auto-failback, status, daemon')
        elif command=='firewall':
            sub = args.argument or 'check'
            if sub == 'check':
                firewall_check(s)
            else:
                raise Error(f'Unknown firewall command: {sub}. Valid: check')
        return 0
    except (Error,KeyboardInterrupt) as e:
        print(f'ERROR: {str(e) if isinstance(e,Error) else "Interrupted."}',file=sys.stderr)
        return 1
    except Exception:
        # Avoid tracebacks containing generated secrets. Stable message for diagnostics.
        print('ERROR: unexpected operation failure; inspect project service states and use diagnostics. No credential data printed.',file=sys.stderr)
        return 1
    finally:
        if fd is not None:
            os.close(fd)
