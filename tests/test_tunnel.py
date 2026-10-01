"""Offline unit/lifecycle tests; no network interfaces or production hosts used."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from tunnel import config, host, manager, render


def conf(role='foreign'):
    return config.validate({'ROLE':role,'FOREIGN_PUBLIC_IP':'203.0.113.10'},require_public=False)


def fake_carriers(c):
    # Distinct syntactically valid dummy key material, never production credentials.
    import base64
    return [{**x,**{k:base64.b64encode(bytes([i*5+j+1])*32).decode()
                   for j,k in enumerate(('private','public','peer_public','psk'))},
             'raw_secret':bytes([i+1]*32).hex()} for i,x in enumerate(config.layout(c))]


class ConfigTests(unittest.TestCase):
    def test_parse_literal_and_no_execution(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'config.env'; p.write_text('# comment\nROLE=iran\nPUBLIC_LISTEN_PORT=9000\n')
            self.assertEqual(config.read_env(p),{'ROLE':'iran','PUBLIC_LISTEN_PORT':'9000'})
            for text in ('ROLE=$(touch /tmp/should-not-exist)','ROLE=foreign\nROLE=iran','BOGUS=value','ROLE="foreign"','ROLE=foreign;id'):
                p.write_text(text)
                with self.assertRaises(config.Error):
                    config.read_env(p)

    def test_roles_and_validation(self):
        for vals in ({'ROLE':'germany'}, {'WIREGUARD_MTU':12}, {'CARRIER_COUNT':0},
                     {'CARRIER_COUNT':9}, {'CARRIER_COUNT':True}, {'CARRIER_COUNT':[]},
                     {'NETWORK_INTERFACE':'eth0;rm'}, {'SELF_HEAL':'sometimes'},
                     {'TUNNEL_NETWORK':'8.8.8.0/24'}, {'TUNNEL_NETWORK':'10.0.0.1/24'},
                     {'TUNNEL_NETWORK':'10.0.0.0/30','CARRIER_COUNT':3},
                     {'WG_PORT_BASE':65000}, {'LOCAL_PORT_BASE':52894},
                     {'PUBLIC_LISTEN_PORT':42094}, {'FOREIGN_PUBLIC_IP':'127.0.0.1'}):
            with self.subTest(vals=vals),self.assertRaises(config.Error):
                config.validate({**conf(),**vals})
        self.assertEqual(config.validate({'FOREIGN_PUBLIC_IP':'1.1.1.1'})['CARRIER_COUNT'],3)

    def test_layout_and_mtu(self):
        c=conf(); xs=config.layout(c)
        self.assertEqual([x['name'] for x in xs],['wg9094','wg9095','wg9096'])
        self.assertEqual([x['raw_port'] for x in xs],[42094,42095,42096])
        self.assertEqual([x['foreign_ip'] for x in xs],['10.203.0.2','10.203.0.6','10.203.0.10'])
        self.assertEqual(c['WIREGUARD_MTU'],900)
        for role in ('iran','foreign'):
            c=conf(role); c.update(NETWORK_INTERFACE='ens3',LOCAL_IP='192.0.2.1')
            x=fake_carriers(c)[0]
            wg=render.wireguard(c,x)
            self.assertIn('Table = off',wg)
            self.assertIn('AllowedIPs = '+('10.203.0.2' if role=='iran' else '10.203.0.1')+'/32',wg)
            self.assertNotIn('0.0.0.0/0',wg)
            for opt in ('--raw-mode icmp','--cipher-mode xor','--auth-mode simple','--sock-buf 10240','--force-sock-buf','--log-level 2'):
                self.assertIn(opt,render.udp2raw(c,x))

    def test_cpu_mapping_sparse_and_small(self):
        self.assertEqual(config.cpu_mapping(3,[2]),[2,2,2])
        self.assertEqual(config.cpu_mapping(3,[2,4]),[2,4,2])
        self.assertEqual(config.cpu_mapping(3,[1,2,3,4,5,6,7,8]),[1,2,3])
        with self.assertRaises(config.Error):
            config.cpu_mapping(3,[])

    def test_os_allowlist(self):
        for ident,vs in [('ubuntu',['22.04','24.04','26.04']),('debian',['12','13'])]:
            for v in vs:
                config.supported_os({'ID':ident,'VERSION_ID':v})
        for x in ({'ID':'arch','VERSION_ID':'rolling'},{'ID':'debian','VERSION_ID':'11'},{'ID':'ubuntu','VERSION_ID':'25.10'}):
            with self.assertRaises(config.Error):
                config.supported_os(x)

    def test_unsupported_host_stops_before_any_command(self):
        with patch('tunnel.host.os_info',return_value={'ID':'arch','VERSION_ID':'rolling'}),patch('tunnel.host.run') as run:
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(config.Error):
                host.preflight(conf())
            run.assert_not_called()

    def test_pair_schema_permissions_and_layout(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'peer.json'; c=conf('iran'); xs=fake_carriers(c)
            with patch('tunnel.config.ipv4',side_effect=lambda v,public=False:v):
                data={'schema':1,'config':c,'carriers':xs}
                config.write_json(p,data)
                self.assertEqual(p.stat().st_mode&0o777,0o600)
                self.assertEqual(config.load_pair(p)[1],xs)
                p.chmod(0o644)
                with self.assertRaises(config.Error): config.load_pair(p)
                p.chmod(0o600)
                data['carriers'][0]['name']='eth0'; config.write_json(p,data)
                with self.assertRaises(config.Error): config.load_pair(p)
                p.unlink(); p.symlink_to('/etc/passwd')
                with self.assertRaises(config.Error): config.load_pair(p)

    def test_generation_independence(self):
        counter=iter([f'key{i}' for i in range(9)])
        with patch('tunnel.config.wg_generate',side_effect=lambda *a:next(counter)),patch('tunnel.config.public_key',side_effect=lambda k:'public-'+k):
            f,pair=config.generate(conf())
        self.assertEqual(len({x['private'] for x in f}),3)
        self.assertEqual(len({x['private'] for x in pair['carriers']}),3)
        self.assertEqual(len({x['raw_secret'] for x in f}),3)
        for a,b in zip(f,pair['carriers']):
            self.assertEqual(a['peer_public'],b['public'])
            self.assertEqual(a['public'],b['peer_public'])
            self.assertEqual(a['psk'],b['psk'])
            self.assertNotEqual(a['private'],b['private'])
        self.assertNotIn('key0',[v for x in pair['carriers'] for v in x.values()])

    @unittest.skipUnless(__import__('shutil').which('wg'),'wg binary unavailable')
    def test_real_generated_keys(self):
        f,p=config.generate(conf())
        config.validate_carriers(conf(),f)
        config.validate_carriers(conf('iran'),p['carriers'])
        for a,b in zip(f,p['carriers']):
            self.assertEqual(config.public_key(a['private']),b['peer_public'])
            self.assertEqual(config.public_key(b['private']),a['peer_public'])


class FirewallModel:
    """Stateful iptables API model with pre-existing unrelated rules."""
    def __init__(self):
        self.chains={(t,b):[['-j','UNRELATED']] for t,_,b in render.CHAINS}
        self.calls=[]
    def __call__(self,*args,check=True):
        a=list(map(str,args)); self.calls.append(a)
        table=a[1]; op=a[2]; chain=a[3]; rest=a[4:]; key=(table,chain)
        code=0
        if op=='-N': self.chains[key]=[]
        elif op=='-S': code=0 if key in self.chains else 1
        elif op=='-F': self.chains[key]=[]
        elif op=='-X': del self.chains[key]
        elif op=='-C': code=0 if rest in self.chains.get(key,[]) else 1
        elif op=='-A': self.chains[key].append(rest)
        elif op=='-I': self.chains[key].insert(int(rest[0])-1,rest[1:])
        elif op=='-D': self.chains[key].remove(rest)
        else: raise AssertionError(op)
        return subprocess.CompletedProcess(args,code,stdout='',stderr='')

class FirewallTests(unittest.TestCase):
    def test_idempotent_and_uninstall_preserves_unrelated_rules(self):
        c=conf('iran'); c['NETWORK_INTERFACE']='ens3'
        s={'config':c,'carriers':fake_carriers(c)}
        model=FirewallModel(); original=copy.deepcopy(model.chains)
        with patch('tunnel.host.ipt',model):
            host.firewall_start(s); once=copy.deepcopy(model.chains)
            host.firewall_start(s); self.assertEqual(once,model.chains)
            self.assertTrue(host.firewall_healthy(s))
            model.chains[('nat','IT2_DNAT')].pop()
            self.assertFalse(host.firewall_healthy(s))
            host.firewall_stop(); self.assertEqual(original,model.chains)
            host.firewall_stop(); self.assertEqual(original,model.chains)
        for a in model.calls:
            if a[2] in ('-F','-X'):
                self.assertTrue(a[3].startswith('IT2_'))

    def test_first_packet_nat_flow_affinity_and_scoping(self):
        c=conf('iran'); c['NETWORK_INTERFACE']='ens3'
        rules=render.firewall_rules(c,config.layout(c))
        tcp=[a for t,ch,a in rules if ch=='IT2_DNAT' and 'tcp' in a]
        udp=[a for t,ch,a in rules if ch=='IT2_DNAT' and 'udp' in a]
        self.assertEqual(len(tcp),3); self.assertEqual(len(udp),3)
        for a in tcp:
            self.assertIn('--syn',a); self.assertIn('LOCAL',a)
        for a in udp:
            self.assertNotIn('--syn',a)
        self.assertEqual([a[a.index('--every')+1] for a in tcp if '--every' in a],['3','2'])
        self.assertEqual([a[a.index('--every')+1] for a in udp if '--every' in a],['3','2'])
        self.assertFalse(any(t=='mangle' and '--mode' in a for t,ch,a in rules))
        self.assertFalse(any(ch=='IT2_FWD' and a[-1]=='DROP' for t,ch,a in rules))
        for t,ch,a in rules:
            if ch=='IT2_MSS': self.assertIn('--clamp-mss-to-pmtu',a)
            if ch=='IT2_SNAT': self.assertIn('DNAT',a)

    def test_existing_nat_conflicts_include_ranges_and_custom_chains(self):
        for text in ('-A OTHER -p tcp --dport 9094 -j DNAT --to-destination 10.0.0.2',
                     '-A OTHER -p udp -m multiport --dports 8000,9000:9100 -j REDIRECT',
                     '-A PREROUTING -j DNAT --to-destination 10.0.0.2'):
            self.assertTrue(host.nat_port_conflict(text,9094))
        self.assertFalse(host.nat_port_conflict('-A OTHER -p tcp --dport 8080 -j DNAT --to-destination 10.0.0.2',9094))
        self.assertFalse(host.nat_port_conflict('-A INPUT -p tcp --dport 9094 -j ACCEPT',9094))

    def test_icmp_suppression_narrow_identifier(self):
        c=conf(); c['NETWORK_INTERFACE']='ens3'
        rules=render.firewall_rules(c,config.layout(c))
        for t,ch,a in rules:
            if 'icmp' in a and a[-1]=='DROP':
                self.assertIn('--u32',a)
                self.assertIn('0>>22&0x3C@4>>16&0xFFFF=', ' '.join(a))

    def test_unit_failure_isolation_and_affinity(self):
        c=conf(); us=render.units(c,fake_carriers(c),[2,4])
        self.assertIn('CPUAffinity=2',us['icmp-tunnel-raw-wg9094.service'])
        self.assertIn('CPUAffinity=4',us['icmp-tunnel-raw-wg9095.service'])
        self.assertIn('CPUAffinity=2',us['icmp-tunnel-raw-wg9096.service'])
        for i in range(3):
            u=us[f'icmp-tunnel-raw-wg{9094+i}.service']
            self.assertIn('RestartSec=10',u); self.assertIn('StartLimitBurst=5',u)
            self.assertNotIn('-k ',u)
            self.assertIn('StandardOutput=null',u)
            self.assertNotIn(f'wg{9094+(i+1)%3}',u)
        self.assertNotIn('Requires=icmp-tunnel-raw',us['icmp-tunnel-wg-wg9094.service'])


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.patches=[]
        for attr,val in {'ETC':self.root/'etc','APP':self.root/'app','VAR':self.root/'var',
                         'SYSFILE':self.root/'sysctl.conf','UNITDIR':self.root/'units','CLI':self.root/'tunnelctl'}.items():
            p=patch.object(host,attr,val); p.start(); self.patches.append(p)
        host.UNITDIR.mkdir(); host.VAR.mkdir(); host.ETC.mkdir(); host.APP.mkdir()
        for attr,val in {'STATE':host.ETC/'state.json','PAIR':host.ETC/'peer.json'}.items():
            p=patch.object(manager,attr,val); p.start(); self.patches.append(p)
        c=conf('iran'); c.update(NETWORK_INTERFACE='ens3',LOCAL_IP='192.0.2.1',PHYSICAL_ROUTE={'dev':'ens3'})
        self.s={'owner':manager.MARKER,'schema':1,'version':manager.version(),'config':c,
                'carriers':fake_carriers(c),'original_sysctl':{k:'original' for k in render.SYSCTL}}
        config.write_json(manager.STATE,self.s)
        self.output=contextlib.redirect_stdout(io.StringIO()); self.output.__enter__()
        self.err=contextlib.redirect_stderr(io.StringIO()); self.err.__enter__()
    def tearDown(self):
        self.output.__exit__(None,None,None); self.err.__exit__(None,None,None)
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()
    def loaded(self):
        return self.s
    def runner(self,args,check=True,**kw):
        out='active\n' if args[0]=='systemctl' else ''
        return subprocess.CompletedProcess(args,0,stdout=out,stderr='')

    def test_repeat_install_never_regenerates_keys(self):
        with patch('tunnel.manager.load_state',self.loaded),patch('tunnel.manager.generate') as gen:
            with self.assertRaises(config.Error): manager.install(self.s['config'])
            gen.assert_not_called()

    def test_sysctl_restore_respects_intervening_admin_changes(self):
        changed_key='net.ipv4.ip_forward'; calls=[]
        def run(args,**kw):
            calls.append(args)
            out='0' if changed_key in args else render.SYSCTL.get(args[-1],'')
            return subprocess.CompletedProcess(args,0,stdout=out,stderr='')
        with patch('tunnel.host.run',side_effect=run): manager.restore_sysctl(self.s)
        self.assertFalse(any(a[-1]==changed_key+'=original' for a in calls))
        self.assertTrue(any(a[-1]=='net.core.default_qdisc=original' for a in calls))

    def test_cleanup_only_owned_files_and_units(self):
        unrelated=host.UNITDIR/'ssh.service'; unrelated.write_text('keep')
        for name in manager.unit_names(self.s): (host.UNITDIR/name).write_text('owned')
        calls=[]
        with patch('tunnel.host.run',side_effect=lambda a,**kw: calls.append(a) or self.runner(a)),patch('tunnel.host.firewall_stop'):
            manager.cleanup(self.s)
        self.assertTrue(unrelated.exists())
        deleted=[a[-1] for a in calls if a[:3]==['ip','link','delete']]
        self.assertEqual(deleted,[x['name'] for x in self.s['carriers']])
        self.assertFalse(any('default' in a for a in calls))
        self.assertFalse(any(a[0]=='apt-get' for a in calls))

    def test_redaction_known_and_generic_credentials(self):
        s=self.s; values=[x[k] for x in s['carriers'] for k in ('private','psk','raw_secret')]
        text=' '.join(values)+'\npassword=abc\npassword="abc def"\nAuthorization: Bearer abc\n-k \'abc def\'\ntoken: abc\n-k abc\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n'
        out=manager.redact(text,s)
        for v in values: self.assertNotIn(v,out)
        self.assertNotIn('abc',out)
        self.assertIn('[REDACTED]',out)

    def test_health_threshold_cooldown_one_carrier_only(self):
        self.s['config']['SELF_HEAL']='yes'; restarts=[]
        with patch('tunnel.manager.secure_dir',lambda p:p.mkdir(exist_ok=True)),patch('tunnel.manager.probe',return_value=['failed']),patch('tunnel.host.firewall_healthy',return_value=True),patch('tunnel.manager.sysctl_healthy',return_value=True),patch('tunnel.manager.restart_carrier',side_effect=lambda s,i:restarts.append(i)):
            manager.health(self.s,True); manager.health(self.s,True)
            self.assertEqual(restarts,[])
            manager.health(self.s,True); self.assertEqual(restarts,[1])
            manager.health(self.s,True); self.assertEqual(restarts,[1,2])
            manager.health(self.s,True); self.assertEqual(restarts,[1,2,3])
            for _ in range(5): manager.health(self.s,True)
            self.assertEqual(restarts,[1,2,3])
        with patch('tunnel.manager.secure_dir',lambda p:p.mkdir(exist_ok=True)),patch('tunnel.manager.probe',return_value=['failed']),patch('tunnel.host.firewall_healthy',return_value=False),patch('tunnel.manager.restart_carrier') as restart:
            manager.health(self.s,True); restart.assert_not_called()

    def test_transaction_failure_restores_keys_code_and_units(self):
        host.SYSFILE.write_text('original sysctl')
        (host.APP/'VERSION').write_text('original code')
        for name in manager.unit_names(self.s): (host.UNITDIR/name).write_text('original unit')
        config.write_json(manager.PAIR,{'test':'original pairing'})
        original=manager.STATE.read_bytes(); original_pair=manager.PAIR.read_bytes(); attempts=[]
        def rendered(s):
            (host.APP/'VERSION').write_text('bad partial update')
            manager.STATE.write_text('broken')
            raise config.Error('injected render failure')
        with patch('tunnel.manager.secure_dir',lambda p:p.mkdir(exist_ok=True)),patch('tunnel.manager.load_state',self.loaded),patch('tunnel.manager.stop'),patch('tunnel.manager.install_rendered',side_effect=rendered),patch('tunnel.host.run',side_effect=self.runner),patch('tunnel.manager.apply_sysctl'),patch('tunnel.manager.start',side_effect=lambda s:attempts.append(s)):
            with self.assertRaises(config.Error): manager.transactional_update(self.s,manager.ROOT,pair_bundle={'test':'new pairing'})
        self.assertEqual(manager.STATE.read_bytes(),original)
        self.assertEqual(manager.PAIR.read_bytes(),original_pair)
        self.assertEqual((host.APP/'VERSION').read_text(),'original code')
        self.assertEqual(attempts,[self.s])
        self.assertFalse((host.VAR/'transaction.json').exists())

    def test_restore_rejects_archive_paths_before_mutating(self):
        p=self.root/'malicious.tar.gz'
        with tarfile.open(p,'w:gz') as t:
            info=tarfile.TarInfo('../../etc/passwd'); info.size=1; t.addfile(info,io.BytesIO(b'x'))
        p.chmod(0o600)
        with patch('tunnel.manager.backup') as backup,patch('tunnel.manager.transactional_update') as update:
            with self.assertRaises(config.Error): manager.restore(self.s,p)
            backup.assert_not_called(); update.assert_not_called()

    def test_offline_dry_run_no_mutations_for_both_roles(self):
        for role in ('foreign','iran'):
            with patch('tunnel.manager.install') as install,patch('tunnel.host.run') as run,patch('tunnel.manager.lock') as lock:
                self.assertEqual(manager.main(['install','--dry-run','--offline','--role',role]),0)
                install.assert_not_called(); run.assert_not_called(); lock.assert_not_called()


    def test_install_role_flows_and_injected_rollback(self):
        import shutil
        for role, fail in [('foreign',False),('iran',False),('foreign',True),('iran',True)]:
            for path in (host.ETC,host.APP,host.VAR):
                shutil.rmtree(path,ignore_errors=True)
            c=conf(role); c.update(NETWORK_INTERFACE='ens3',LOCAL_IP='192.0.2.1',PHYSICAL_ROUTE={'dev':'ens3'})
            xs=fake_carriers(c)
            bundle={'schema':1,'config':conf('iran'),'carriers':fake_carriers(conf('iran'))}
            def runner(a,**kw):
                if a[0]=='sysctl' and '-n' in a:
                    return subprocess.CompletedProcess(a,0,stdout='original',stderr='')
                if fail and a[:3]==['systemctl','enable','--now'] and 'raw-wg9095' in a[-1]:
                    raise config.Error('injected service-start failure')
                return self.runner(a,**kw)
            def secure(p): p.mkdir(parents=True,exist_ok=True,mode=0o700)
            def binary(stage):
                (stage/'bin/udp2raw').write_text('dummy binary')
            with patch('tunnel.manager.require_root'),patch('tunnel.host.preflight',return_value=[2,4,6]),patch('tunnel.host.install_packages'),patch('tunnel.manager.secure_dir',side_effect=secure),patch('tunnel.manager.build_binary',side_effect=binary),patch('tunnel.config.public_key',side_effect=lambda k:next(x['public'] for x in xs if x['private']==k)),patch('tunnel.manager.public_key',side_effect=lambda k:next(x['public'] for x in xs if x['private']==k)),patch('tunnel.manager.generate',return_value=(xs,bundle)),patch('tunnel.host.run',side_effect=runner),patch('tunnel.host.firewall_stop'):
                if fail:
                    with self.assertRaises(config.Error): manager.install(c,xs if role=='iran' else None)
                    self.assertFalse(host.APP.exists()); self.assertFalse(manager.STATE.exists())
                    self.assertFalse(host.SYSFILE.exists()); self.assertFalse(host.CLI.exists())
                    for name in manager.unit_names({'config':c,'carriers':xs}):
                        self.assertFalse((host.UNITDIR/name).exists())
                else:
                    manager.install(c,xs if role=='iran' else None)
                    saved=json.loads(manager.STATE.read_text())
                    self.assertEqual(saved['config']['ROLE'],role)
                    self.assertEqual(saved['carriers'],xs)
                    self.assertEqual(manager.STATE.stat().st_mode&0o777,0o600)
                    self.assertEqual(manager.PAIR.exists(),role=='foreign')
                    for x in xs:
                        self.assertEqual((host.ETC/'wg'/f'{x['name']}.conf').stat().st_mode&0o777,0o600)

    def test_backup_restore_roundtrip_keeps_current_host_original_sysctl(self):
        p=self.root/'backup.tar.gz'
        with patch('tunnel.manager.load_state',self.loaded),patch('tunnel.manager.safe_destination',side_effect=lambda x:Path(x)):
            manager.backup(p)
        self.assertEqual(p.stat().st_mode&0o777,0o600)
        self.assertTrue(p.exists())
        with patch('tunnel.config.ipv4',side_effect=lambda v,public=False:v),patch('tunnel.manager.public_key',side_effect=lambda k:next(x['public'] for x in self.s['carriers'] if x['private']==k)),patch('tunnel.manager.backup'),patch('tunnel.manager.transactional_update') as update:
            manager.restore(self.s,p)
            updated=update.call_args.args[0]
            self.assertEqual(updated['carriers'],self.s['carriers'])
            self.assertEqual(updated['original_sysctl'],self.s['original_sysctl'])

    def test_upgrade_preserves_identity_and_takes_backup_first(self):
        order=[]
        with patch('tunnel.host.preflight'),patch('tunnel.manager.backup',side_effect=lambda:order.append('backup')),patch('tunnel.manager.transactional_update',side_effect=lambda s,source,rebuild=False:order.append(('update',s,rebuild))):
            manager.upgrade(self.s,manager.ROOT)
        self.assertEqual(order[0],'backup')
        self.assertEqual(order[1][1]['carriers'],self.s['carriers'])
        self.assertTrue(order[1][2])

    def test_sysctl_tab_whitespace_healthy(self):
        with patch('tunnel.host.run',side_effect=lambda a,**kw:subprocess.CompletedProcess(a,0,stdout=render.SYSCTL[a[-1]].replace(' ','\t')+'\n',stderr='')):
            self.assertTrue(manager.sysctl_healthy())


    def test_interactive_menu_roles_and_noninteractive_config(self):
        from types import SimpleNamespace
        args=SimpleNamespace(config=None,role=None,peer=None,dry_run=False,offline=False)
        with patch('tunnel.manager.detect_public_source',return_value='1.1.1.1'),patch('builtins.input',side_effect=['1','']):
            command,c,pair=manager.choose_install(args)
        self.assertEqual(command,'install'); self.assertEqual(c['ROLE'],'foreign'); self.assertIsNone(pair)
        pairfile=self.root/'import.json'; pairc=conf('iran'); pairc['FOREIGN_PUBLIC_IP']='1.1.1.1'
        data={'schema':1,'config':pairc,'carriers':fake_carriers(pairc)}
        config.write_json(pairfile,data)
        with patch('builtins.input',side_effect=['2',str(pairfile)]):
            command,c,pair=manager.choose_install(args)
        self.assertEqual(c['ROLE'],'iran'); self.assertEqual(pair,data['carriers'])
        env=self.root/'config.env'; env.write_text('ROLE=iran\nPEER_FILE='+str(pairfile)+'\n')
        args.config=str(env)
        command,c,pair=manager.choose_install(args)
        self.assertEqual(c['ROLE'],'iran'); self.assertEqual(pair,data['carriers'])
        args.role='foreign'
        with self.assertRaises(config.Error): manager.choose_install(args)


    def test_recovery_hourly_attempt_limit(self):
        c=conf('iran'); c.update(CARRIER_COUNT=1,SELF_HEAL='yes',HEALTH_FAILURES=2)
        self.s.update(config=c,carriers=fake_carriers(c))
        clock=[1000000]; restarts=[]
        with patch('tunnel.manager.secure_dir',lambda p:p.mkdir(exist_ok=True)),patch('tunnel.manager.probe',return_value=['failed']),patch('tunnel.host.firewall_healthy',return_value=True),patch('tunnel.manager.sysctl_healthy',return_value=True),patch('tunnel.manager.restart_carrier',side_effect=lambda s,i:restarts.append(clock[0])),patch('tunnel.manager.time.time',side_effect=lambda:clock[0]):
            for _ in range(10):
                manager.health(self.s,True); clock[0]+=300
            self.assertEqual(len(restarts),3)
            clock[0]+=3600
            manager.health(self.s,True)
            self.assertEqual(len(restarts),4)

    def test_uninstall_retains_backups_and_ownership_marker(self):
        config.write_json(host.VAR/'owner.json',{'owner':manager.MARKER})
        (host.VAR/'backups').mkdir(); (host.VAR/'backups'/'saved.tar.gz').write_text('dummy protected backup')
        with patch('tunnel.host.run',side_effect=self.runner),patch('tunnel.host.firewall_stop'):
            manager.cleanup(self.s)
        self.assertTrue((host.VAR/'backups'/'saved.tar.gz').exists())
        self.assertEqual(json.loads((host.VAR/'owner.json').read_text()),{'owner':manager.MARKER})

if __name__=='__main__': unittest.main(verbosity=2)
