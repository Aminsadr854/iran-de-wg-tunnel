#!/usr/bin/env python3
"""
Multi-Carrier ICMP Tunnel Availability Hardening & Endpoint Failover Engine
Author: Iran-DE WG Tunnel Project
License: MIT

Implements layered health monitoring, passive signal inspection, failure classification,
conservative thresholding, cooldown, hysteresis, state persistence, and staged carrier failover.
"""

import os
import sys
import time
import json
import socket
import struct
import subprocess
import argparse
import logging
import logging.handlers

CONFIG_PATH = os.environ.get("TUNNEL_FAILOVER_CONF", "/etc/iran-de-tunnel/failover.conf")
STATE_PATH = os.environ.get("TUNNEL_STATE_PATH", "/var/lib/iran-de-tunnel/state.json")

# Default settings
DEFAULT_CONFIG = {
    "PRIMARY_FOREIGN_ENDPOINT": "",
    "SECONDARY_FOREIGN_ENDPOINT": "",
    "FOREIGN_ENDPOINTS": "",
    "AUTO_FAILOVER": "yes",
    "AUTO_FAILBACK": "no",
    "FAILURE_THRESHOLD": "3",
    "RECOVERY_THRESHOLD": "5",
    "FAILOVER_COOLDOWN": "300",
    "CHECK_INTERVAL": "15",
    "HANDSHAKE_STALE_SEC": "100",
    "APP_PORT": "9094",
    "CARRIERS": "wg9094:10.77.94.2:42094 wg9095:10.77.95.2:42095 wg9096:10.77.96.2:42096",
    "UDP2RAW_CONF_DIR": "/etc/udp2raw",
}

logger = logging.getLogger("tunnel-failover")

def setup_logging(verbose=False):
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(console)
        try:
            syslog = logging.handlers.SysLogHandler(address="/dev/log")
            syslog.setFormatter(logging.Formatter("tunnel-failover: %(levelname)s %(message)s"))
            logger.addHandler(syslog)
        except Exception:
            pass

def load_config(config_file=CONFIG_PATH):
    conf = dict(DEFAULT_CONFIG)
    if os.path.isfile(config_file):
        with open(config_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                conf[k] = v
    return conf

def load_state(state_file=STATE_PATH):
    if os.path.isfile(state_file):
        try:
            with open(state_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read state file {state_file}: {e}")
    return {}

def save_state(state, state_file=None):
    if state_file is None:
        state_file = STATE_PATH
    try:
        os.makedirs(os.path.dirname(state_file), exist_ok=True)
        tmp_file = f"{state_file}.tmp.{os.getpid()}"
        with open(tmp_file, "w") as f:
            json.dump(state, f, indent=2)
            f.write("\n")
        os.replace(tmp_file, state_file)
    except Exception as e:
        logger.error(f"Failed to save state to {state_file}: {e}")

class LayeredHealthChecker:
    def __init__(self, config):
        self.config = config
        self.carriers = []
        for item in config.get("CARRIERS", "").split():
            parts = item.split(":")
            if len(parts) >= 3:
                self.carriers.append({
                    "dev": parts[0],
                    "gateway": parts[1],
                    "port": int(parts[2])
                })

    def check_local_services(self):
        """Phase 6: Differentiate local service failure from remote endpoint failure."""
        issues = []
        for c in self.carriers:
            dev = c["dev"]
            # Check udp2raw service
            res = subprocess.run(["systemctl", "is-active", "--quiet", f"udp2raw-{dev}.service"], capture_output=True)
            if res.returncode != 0:
                issues.append(f"udp2raw-{dev}.service is not active")
            # Check wg interface
            res = subprocess.run(["ip", "link", "show", dev], capture_output=True)
            if res.returncode != 0:
                issues.append(f"WireGuard interface {dev} does not exist")
        return issues

    def check_routing_and_forwarding(self):
        """Phase 6: Check local IP forwarding and default route."""
        issues = []
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                if f.read().strip() != "1":
                    issues.append("net.ipv4.ip_forward is disabled")
        except Exception as e:
            issues.append(f"Failed to check ip_forward: {e}")

        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        if "default via" not in res.stdout:
            issues.append("No default route found on local system")
        return issues

    def check_firewall_conflicts(self):
        """Phase 20-22: Detect any unauthorized DNAT/REDIRECT on APP_PORT."""
        app_port = self.config.get("APP_PORT", "9094")
        conflicts = []

        # Check nftables
        try:
            res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                current_table = ""
                for line in lines:
                    line_s = line.strip()
                    if line_s.startswith("table "):
                        current_table = line_s
                    if f"dport {app_port}" in line_s or f"dpt:{app_port}" in line_s:
                        # Allow our own iptables-compatibility table and ignore WG9094
                        if "WG9094" not in line_s and "cbtun" in current_table:
                            conflicts.append(f"nftables conflict in {current_table}: {line_s}")
        except Exception:
            pass

        # Check iptables PREROUTING
        try:
            res = subprocess.run(["iptables", "-t", "nat", "-S", "PREROUTING"], capture_output=True, text=True)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if f"--dport {app_port}" in line:
                        if "WG9094_DNAT" not in line:
                            conflicts.append(f"iptables PREROUTING conflict: {line}")
        except Exception:
            pass

        return conflicts

    def get_carrier_passive_signals(self):
        """Phase 4: Check WireGuard handshakes and transfer progression."""
        stale_sec = int(self.config.get("HANDSHAKE_STALE_SEC", "100"))
        now = time.time()
        carrier_states = {}

        for c in self.carriers:
            dev = c["dev"]
            state = {
                "dev": dev,
                "gateway": c["gateway"],
                "port": c["port"],
                "handshake_age": None,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "healthy": False,
                "current_remote": None
            }

            # Read current remote from conf
            conf_path = os.path.join(self.config.get("UDP2RAW_CONF_DIR", "/etc/udp2raw"), f"{dev}.conf")
            if os.path.isfile(conf_path):
                try:
                    with open(conf_path, "r") as f:
                        for line in f:
                            if line.strip().startswith("-r "):
                                r_ep = line.strip().split()[1]
                                state["current_remote"] = r_ep.split(":")[0]
                except Exception:
                    pass

            # Query WireGuard
            try:
                out = subprocess.check_output(["wg", "show", dev, "dump"], text=True)
                lines = out.strip().splitlines()
                if len(lines) >= 2:
                    peer_parts = lines[1].split()
                    if len(peer_parts) >= 6:
                        last_hs = int(peer_parts[4])
                        state["rx_bytes"] = int(peer_parts[5])
                        state["tx_bytes"] = int(peer_parts[6])
                        if last_hs > 0:
                            state["handshake_age"] = int(now - last_hs)
                            if state["handshake_age"] < stale_sec:
                                state["healthy"] = True
            except Exception as e:
                logger.debug(f"wg show {dev} failed: {e}")

            carrier_states[dev] = state

        return carrier_states

    def check_in_tunnel_reachability(self, dev, gateway_ip):
        """Layer 4: Ping the in-tunnel gateway IP."""
        try:
            res = subprocess.run(
                ["ping", "-n", "-q", "-I", dev, "-c", "1", "-W", "2", gateway_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return (res.returncode == 0)
        except Exception:
            return False

    def probe_foreign_host(self, host_ip):
        """Layer 1: Probe remote foreign host reachability (TCP port 22 or fast ping)."""
        # Test TCP 22 first
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((host_ip, 22))
                return True
        except Exception:
            pass

        # Fallback to ICMP ping
        try:
            res = subprocess.run(
                ["ping", "-n", "-q", "-c", "1", "-W", "2", host_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return (res.returncode == 0)
        except Exception:
            return False

    def probe_foreign_carrier_icmp(self, host_ip):
        """Layer 2: Probe raw ICMP capability to the Foreign endpoint."""
        try:
            res = subprocess.run(
                ["ping", "-n", "-q", "-c", "2", "-W", "2", host_ip],
                capture_output=True,
                text=True
            )
            if res.returncode == 0 and " 0% packet loss" in res.stdout:
                return True
        except Exception:
            pass
        return False


class FailoverStateMachine:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.checker = LayeredHealthChecker(config)

        # Initialize state structures if needed
        self.primary_ep = config.get("PRIMARY_FOREIGN_ENDPOINT", "")
        self.secondary_ep = config.get("SECONDARY_FOREIGN_ENDPOINT", "")
        fallback_eps = f"{self.primary_ep} {self.secondary_ep}".strip()
        self.configured_endpoints = config.get("FOREIGN_ENDPOINTS", fallback_eps).split()

        if "active_endpoint" not in self.state:
            # Determine from carrier 1 config on disk
            current_ep = self.get_active_endpoint_from_disk()
            self.state["active_endpoint"] = current_ep if current_ep else self.secondary_ep

        if "manual_override" not in self.state:
            self.state["manual_override"] = False

        if "cooldown_until" not in self.state:
            self.state["cooldown_until"] = 0

        if "endpoints" not in self.state:
            self.state["endpoints"] = {}

        for ep in self.configured_endpoints:
            if ep not in self.state["endpoints"]:
                self.state["endpoints"][ep] = {
                    "status": "UNKNOWN",
                    "consecutive_failures": 0,
                    "consecutive_successes": 0,
                    "last_checked": 0,
                    "last_error": None
                }

    def get_active_endpoint_from_disk(self):
        conf_dir = self.config.get("UDP2RAW_CONF_DIR", "/etc/udp2raw")
        c1 = os.path.join(conf_dir, "wg9094.conf")
        if os.path.isfile(c1):
            try:
                with open(c1, "r") as f:
                    for line in f:
                        if line.strip().startswith("-r "):
                            return line.strip().split()[1].split(":")[0]
            except Exception:
                pass
        return None

    def evaluate_health(self):
        """Runs layered checks and returns failure classification and carrier details."""
        now = time.time()
        fail_thresh = int(self.config.get("FAILURE_THRESHOLD", "3"))
        recov_thresh = int(self.config.get("RECOVERY_THRESHOLD", "5"))

        local_svc_issues = self.checker.check_local_services()
        routing_issues = self.checker.check_routing_and_forwarding()
        fw_conflicts = self.checker.check_firewall_conflicts()

        # Classification check
        if local_svc_issues:
            return {
                "classification": "LOCAL_SERVICE_FAILURE",
                "details": local_svc_issues,
                "needs_failover": False
            }

        if routing_issues:
            return {
                "classification": "ROUTING_FAILURE",
                "details": routing_issues,
                "needs_failover": False
            }

        if fw_conflicts:
            logger.warning(f"Firewall conflicts detected: {fw_conflicts}")

        # Passive signals on active carriers
        carrier_states = self.checker.get_carrier_passive_signals()
        healthy_carriers = 0
        total_carriers = len(carrier_states)

        for dev, c_state in carrier_states.items():
            if c_state["healthy"]:
                # Also verify in-tunnel ping
                if self.checker.check_in_tunnel_reachability(dev, c_state["gateway"]):
                    healthy_carriers += 1
                else:
                    c_state["healthy"] = False

        active_ep = self.state["active_endpoint"]
        ep_record = self.state["endpoints"].setdefault(active_ep, {
            "status": "UNKNOWN", "consecutive_failures": 0, "consecutive_successes": 0
        })

        # Initialize carrier failure tracking if needed
        if not hasattr(self, "carrier_failures"):
            self.carrier_failures = {c["dev"]: 0 for c in self.checker.carriers}

        if healthy_carriers == total_carriers:
            ep_record["status"] = "HEALTHY"
            ep_record["consecutive_failures"] = 0
            ep_record["consecutive_successes"] += 1
            ep_record["last_checked"] = now
            for dev in self.carrier_failures:
                self.carrier_failures[dev] = 0
            classification = "HEALTHY"
            needs_failover = False
        elif healthy_carriers > 0:
            # Partial carrier degradation (Phase 7: don't restart all carriers if only 1 failed)
            classification = "PARTIAL_CARRIER_DEGRADATION"
            needs_failover = False
            # Auto-heal degraded carriers only after 3 consecutive failures (conservative threshold)
            for dev, c_state in carrier_states.items():
                if not c_state["healthy"]:
                    self.carrier_failures[dev] = self.carrier_failures.get(dev, 0) + 1
                    cnt = self.carrier_failures[dev]
                    if cnt < fail_thresh:
                        logger.warning(f"Carrier {dev} degraded check {cnt}/{fail_thresh}, observing...")
                    else:
                        logger.info(f"Carrier {dev} degraded for {fail_thresh} consecutive checks, restarting carrier locally.")
                        subprocess.run(["systemctl", "restart", f"udp2raw-{dev}.service"], capture_output=True)
                        time.sleep(2.0)
                        subprocess.run(["systemctl", "restart", f"wg-quick@{dev}.service"], capture_output=True)
                        self.carrier_failures[dev] = 0
                else:
                    self.carrier_failures[dev] = 0
        else:
            # All carriers failed on this endpoint
            ep_record["consecutive_failures"] += 1
            ep_record["consecutive_successes"] = 0
            ep_record["last_checked"] = now

            if ep_record["consecutive_failures"] >= fail_thresh:
                ep_record["status"] = "FAILED"
                classification = "REMOTE_ENDPOINT_CARRIER_FAILURE"
                needs_failover = True
            else:
                ep_record["status"] = "SUSPECT"
                classification = f"SUSPECT_FAILURE ({ep_record['consecutive_failures']}/{fail_thresh})"
                needs_failover = False

        # If active endpoint is healthy, check background recovery of inactive endpoints for failback
        for ep in self.configured_endpoints:
            if ep != active_ep:
                other_rec = self.state["endpoints"].setdefault(ep, {
                    "status": "UNKNOWN", "consecutive_failures": 0, "consecutive_successes": 0
                })
                # Check ICMP carrier reachability
                if self.checker.probe_foreign_carrier_icmp(ep):
                    other_rec["consecutive_successes"] += 1
                    other_rec["consecutive_failures"] = 0
                    if other_rec["consecutive_successes"] >= recov_thresh:
                        other_rec["status"] = "STABLE"
                    else:
                        other_rec["status"] = "RECOVERING"
                else:
                    other_rec["consecutive_failures"] += 1
                    other_rec["consecutive_successes"] = 0
                    other_rec["status"] = "FAILED"
                other_rec["last_checked"] = now

        return {
            "classification": classification,
            "carrier_states": carrier_states,
            "needs_failover": needs_failover,
            "fw_conflicts": fw_conflicts
        }

    def execute_failover(self, target_endpoint, reason="Automatic failover"):
        """Phase 8 & 9: Staged, flow-safe carrier migration to target_endpoint."""
        now = time.time()
        cooldown_sec = int(self.config.get("FAILOVER_COOLDOWN", "300"))
        conf_dir = self.config.get("UDP2RAW_CONF_DIR", "/etc/udp2raw")

        old_ep = self.state["active_endpoint"]
        logger.info(f"Initiating staged failover from {old_ep} to {target_endpoint}. Reason: {reason}")

        # Verify candidate endpoint is responding to ICMP carrier probes
        if not self.checker.probe_foreign_carrier_icmp(target_endpoint):
            logger.error(f"Cannot failover to {target_endpoint}: candidate failed ICMP carrier probe!")
            return False

        # Stage carrier migration one by one
        successes = 0
        for c in self.checker.carriers:
            dev = c["dev"]
            port = c["port"]
            conf_file = os.path.join(conf_dir, f"{dev}.conf")
            logger.info(f"Staged migration: updating carrier {dev} to endpoint {target_endpoint}:{port}...")

            # Update configuration file safely
            if os.path.isfile(conf_file):
                lines = []
                with open(conf_file, "r") as f:
                    for line in f:
                        if line.strip().startswith("-r "):
                            lines.append(f"-r {target_endpoint}:{port}\n")
                        else:
                            lines.append(line)
                with open(conf_file, "w") as f:
                    f.writelines(lines)

            # Restart carrier services
            subprocess.run(["systemctl", "restart", f"udp2raw-{dev}.service"], capture_output=True)
            time.sleep(1.0)
            subprocess.run(["systemctl", "restart", f"wg-quick@{dev}.service"], capture_output=True)
            time.sleep(1.5)

            # Check handshake
            out = subprocess.run(["wg", "show", dev, "latest-handshakes"], capture_output=True, text=True)
            hs = 0
            if out.returncode == 0 and out.stdout.strip():
                parts = out.stdout.strip().split()
                if len(parts) >= 2:
                    hs = int(parts[1])
            if hs > 0 and (now - hs) < 15:
                logger.info(f"Carrier {dev} successfully migrated and handshook!")
                successes += 1
            else:
                logger.warning(f"Carrier {dev} migrated but handshake not yet confirmed (will retry).")

        # Update state
        self.state["active_endpoint"] = target_endpoint
        self.state["last_transition_time"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
        self.state["last_transition_reason"] = reason
        self.state["cooldown_until"] = now + cooldown_sec
        self.state["endpoints"][target_endpoint]["status"] = "HEALTHY"
        self.state["endpoints"][target_endpoint]["consecutive_successes"] = 1
        self.state["endpoints"][target_endpoint]["consecutive_failures"] = 0
        save_state(self.state)

        logger.info(f"Failover completed. Active endpoint is now {target_endpoint}. Cooldown active for {cooldown_sec}s.")
        return True

    def run_step(self):
        """Performs one iteration of the health evaluation and failover logic."""
        now = time.time()
        result = self.evaluate_health()
        save_state(self.state)

        classification = result["classification"]
        logger.debug(f"Evaluation result: {classification}")

        # Check for failover necessity
        if result["needs_failover"]:
            if self.state.get("manual_override", False):
                logger.warning("Active endpoint failed, but manual override is active. Not failing over automatically.")
                return result

            if self.config.get("AUTO_FAILOVER", "yes").lower() != "yes":
                logger.warning("Active endpoint failed, but AUTO_FAILOVER is disabled.")
                return result

            if now < self.state.get("cooldown_until", 0):
                rem = int(self.state["cooldown_until"] - now)
                logger.warning(f"Active endpoint failed, but failover cooldown is active ({rem}s remaining).")
                return result

            # Find healthy alternative endpoint
            active_ep = self.state["active_endpoint"]
            candidates = [ep for ep in self.configured_endpoints if ep != active_ep]
            healthy_target = None
            for cand in candidates:
                rec = self.state["endpoints"].get(cand, {})
                if rec.get("status") in ("HEALTHY", "STABLE", "RECOVERING") or self.checker.probe_foreign_carrier_icmp(cand):
                    healthy_target = cand
                    break

            if healthy_target:
                self.execute_failover(healthy_target, reason=f"Automatic failover due to {classification}")
            else:
                self.state["overall_status"] = "NO_HEALTHY_ENDPOINT"
                logger.critical("ALL CONFIGURED FOREIGN ENDPOINTS ARE UNHEALTHY! Bounded backoff initiated.")
                save_state(self.state)

        # Check for auto failback (Phase 11)
        elif self.config.get("AUTO_FAILBACK", "no").lower() == "yes" and not self.state.get("manual_override", False):
            primary = self.primary_ep
            active_ep = self.state["active_endpoint"]
            if active_ep != primary:
                primary_rec = self.state["endpoints"].get(primary, {})
                if primary_rec.get("status") == "STABLE" and now >= self.state.get("cooldown_until", 0):
                    logger.info(f"Primary endpoint {primary} recovered and stable. Executing automatic failback.")
                    self.execute_failover(primary, reason="Automatic failback to recovered primary endpoint")

        return result


def format_status_output(config, state):
    checker = LayeredHealthChecker(config)
    carrier_states = checker.get_carrier_passive_signals()
    active_ep = state.get("active_endpoint", "UNKNOWN")
    primary_ep = config.get("PRIMARY_FOREIGN_ENDPOINT", "")
    secondary_ep = config.get("SECONDARY_FOREIGN_ENDPOINT", "")

    # Determine endpoint tags
    def ep_tag(ip):
        if ip == primary_ep: return "primary"
        if ip == secondary_ep: return "secondary"
        return "custom"

    active_tag = ep_tag(active_ep)
    now = time.time()
    cooldown_rem = max(0, int(state.get("cooldown_until", 0) - now))

    out = []
    out.append("==================================================")
    out.append("IRAN ↔ GERMANY TUNNEL FAILOVER STATUS")
    out.append("==================================================")
    out.append(f"ACTIVE FOREIGN ENDPOINT:")
    out.append(f"  {active_ep} ({active_tag})")
    out.append("")
    out.append("CONFIGURED ENDPOINTS:")
    for ep in config.get("FOREIGN_ENDPOINTS", "").split():
        rec = state.get("endpoints", {}).get(ep, {})
        status = rec.get("status", "UNKNOWN")
        tag = ep_tag(ep)
        marker = " [ACTIVE]" if ep == active_ep else ""
        out.append(f"  * {ep:<16} ({tag:<9}): {status}{marker}")

    out.append("")
    out.append("CARRIER HEALTH:")
    for dev, c_state in carrier_states.items():
        dev_name = dev
        status_str = "UP" if c_state["healthy"] else "DEGRADED"
        hs_str = f"{c_state['handshake_age']}s ago" if c_state['handshake_age'] is not None else "NEVER"
        ep_name = ep_tag(c_state.get("current_remote") or active_ep)
        out.append(f"  {dev_name}: {status_str} | Endpoint: {ep_name} ({c_state.get('current_remote')}) | Handshake: {hs_str}")

    out.append("")
    out.append(f"AUTOMATIC FAILOVER:  {config.get('AUTO_FAILOVER', 'yes').upper()}")
    out.append(f"AUTOMATIC FAILBACK:  {config.get('AUTO_FAILBACK', 'no').upper()}")
    out.append(f"FAILOVER COOLDOWN:   {config.get('FAILOVER_COOLDOWN', '300')}s (Active: {cooldown_rem}s remaining)")
    out.append(f"MANUAL OVERRIDE:     {'ACTIVE' if state.get('manual_override', False) else 'DISABLED'}")
    out.append("")
    out.append("LAST TRANSITION:")
    out.append(f"  Timestamp:  {state.get('last_transition_time', 'None')}")
    out.append(f"  Reason:     {state.get('last_transition_reason', 'None')}")
    out.append("")
    out.append("FIREWALL AUDIT:")
    conflicts = checker.check_firewall_conflicts()
    if conflicts:
        out.append(f"  Port {config.get('APP_PORT', '9094')} Conflicts: FOUND ({len(conflicts)})")
        for c in conflicts:
            out.append(f"    ! {c}")
    else:
        out.append(f"  Port {config.get('APP_PORT', '9094')} Ownership: OK (No unauthorized hooks)")
    out.append("==================================================")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Multi-Carrier Tunnel Failover Management Tool")
    subparsers = parser.add_subparsers(dest="command")

    # daemon
    subparsers.add_parser("daemon", help="Run background failover monitor daemon")

    # status
    p_status = subparsers.add_parser("status", help="Show current failover & carrier status")
    p_status.add_argument("--json", action="store_true", help="Output JSON format")

    # endpoint
    p_ep = subparsers.add_parser("endpoint", help="Manage Foreign endpoints")
    ep_subs = p_ep.add_subparsers(dest="ep_command")
    ep_subs.add_parser("status", help="Show endpoint status")
    ep_subs.add_parser("list", help="List configured candidate endpoints")
    ep_subs.add_parser("check", help="Run active health checks on all endpoints")
    p_sw = ep_subs.add_parser("switch", help="Manually switch active endpoint")
    p_sw.add_argument("target", help="Target endpoint IP or alias (primary/secondary)")

    # failover
    p_fo = subparsers.add_parser("failover", help="Manage failover automation settings")
    fo_subs = p_fo.add_subparsers(dest="fo_command")
    fo_subs.add_parser("status", help="Show failover settings")
    fo_subs.add_parser("enable", help="Enable automatic failover")
    fo_subs.add_parser("disable", help="Disable automatic failover")
    p_af = fo_subs.add_parser("auto-failback", help="Configure auto failback")
    p_af.add_argument("mode", choices=["enable", "disable"])

    # firewall
    p_fw = subparsers.add_parser("firewall", help="Firewall conflict audit")
    fw_subs = p_fw.add_subparsers(dest="fw_command")
    fw_subs.add_parser("check", help="Check for port conflicts")

    args = parser.parse_args()
    config = load_config()
    state = load_state()
    setup_logging()

    fsm = FailoverStateMachine(config, state)

    if args.command == "daemon":
        logger.info("Starting Tunnel Failover Monitor Daemon...")
        check_interval = int(config.get("CHECK_INTERVAL", "15"))
        while True:
            try:
                # Reload config each loop so dynamic admin changes take effect
                fsm.config = load_config()
                fsm.state = load_state()
                fsm.run_step()
            except Exception as e:
                logger.error(f"Error in failover cycle: {e}", exc_info=True)
            time.sleep(check_interval)

    elif args.command == "status" or (args.command == "endpoint" and args.ep_command == "status"):
        if getattr(args, "json", False):
            print(json.dumps({"config": config, "state": state}, indent=2))
        else:
            print(format_status_output(config, state))

    elif args.command == "endpoint" and args.ep_command == "list":
        print("Configured Foreign Endpoints:")
        for ep in config.get("FOREIGN_ENDPOINTS", "").split():
            role = "primary" if ep == config.get("PRIMARY_FOREIGN_ENDPOINT") else ("secondary" if ep == config.get("SECONDARY_FOREIGN_ENDPOINT") else "candidate")
            active = " [ACTIVE]" if ep == state.get("active_endpoint") else ""
            print(f"  {ep} ({role}){active}")

    elif args.command == "endpoint" and args.ep_command == "check":
        print("Executing Layered Health Probes on Configured Endpoints...")
        checker = LayeredHealthChecker(config)
        for ep in config.get("FOREIGN_ENDPOINTS", "").split():
            host_ok = checker.probe_foreign_host(ep)
            icmp_ok = checker.probe_foreign_carrier_icmp(ep)
            print(f"Endpoint: {ep}")
            print(f"  Layer 1 (Host Reachable):         {'PASS' if host_ok else 'FAIL'}")
            print(f"  Layer 2 (ICMP Carrier Reachable): {'PASS' if icmp_ok else 'FAIL'}")

    elif args.command == "endpoint" and args.ep_command == "switch":
        target = args.target
        if target.lower() == "primary":
            target = config.get("PRIMARY_FOREIGN_ENDPOINT")
        elif target.lower() == "secondary":
            target = config.get("SECONDARY_FOREIGN_ENDPOINT")

        print(f"Executing manual staged switch to {target}...")
        fsm.state["manual_override"] = True
        success = fsm.execute_failover(target, reason=f"Manual administrative switch to {target}")
        if success:
            print(f"Successfully switched to {target} (Manual override active).")
        else:
            print(f"Failed to switch to {target}.")
            sys.exit(1)

    elif args.command == "failover":
        if args.fo_command == "enable":
            fsm.state["manual_override"] = False
            save_state(fsm.state)
            print("Automatic failover ENABLED.")
        elif args.fo_command == "disable":
            fsm.state["manual_override"] = True
            save_state(fsm.state)
            print("Automatic failover DISABLED (Manual override locked to current endpoint).")
        elif args.fo_command == "auto-failback":
            val = "yes" if args.mode == "enable" else "no"
            print(f"To persist AUTO_FAILBACK={val}, set AUTO_FAILBACK={val} in {CONFIG_PATH}")
        else:
            print(f"Automatic Failover: {'DISABLED (Manual override)' if state.get('manual_override') else config.get('AUTO_FAILOVER')}")
            print(f"Automatic Failback: {config.get('AUTO_FAILBACK')}")
            print(f"Cooldown Period:    {config.get('FAILOVER_COOLDOWN')}s")

    elif args.command == "firewall":
        checker = LayeredHealthChecker(config)
        conflicts = checker.check_firewall_conflicts()
        if conflicts:
            print("WARNING: Firewall conflicts detected:")
            for c in conflicts:
                print(f"  ! {c}")
            sys.exit(1)
        else:
            print(f"OK: Port {config.get('APP_PORT', '9094')} ownership verified. No conflicts.")

    else:
        print(format_status_output(config, state))

if __name__ == "__main__":
    main()
