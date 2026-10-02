#!/usr/bin/env python3
"""
Unit tests for the Tunnel Availability & Failover State Machine.
Tests all failure modes, threshold hysteresis, cooldown, manual overrides,
and failure classifications without needing live network access.
"""

import unittest
from unittest.mock import MagicMock, patch
import json
import os
import sys
import tempfile
import time

# Add iran directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "iran")))
import importlib
engine = importlib.import_module("tunnel-failover-engine")

class TestFailoverStateMachine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "failover.conf")
        self.state_path = os.path.join(self.temp_dir, "state.json")
        os.environ["TUNNEL_STATE_PATH"] = self.state_path
        engine.STATE_PATH = self.state_path
        self.udp2raw_dir = os.path.join(self.temp_dir, "udp2raw")
        os.makedirs(self.udp2raw_dir, exist_ok=True)

        # Create dummy carrier configs
        for dev, port in [("wg9094", 42094), ("wg9095", 42095), ("wg9096", 42096)]:
            with open(os.path.join(self.udp2raw_dir, f"{dev}.conf"), "w") as f:
                f.write(f"-r 198.51.100.1:{port}\n-l 127.0.0.1:{port}\n")

        self.config = {
            "PRIMARY_FOREIGN_ENDPOINT": "198.51.100.1",
            "SECONDARY_FOREIGN_ENDPOINT": "198.51.100.2",
            "FOREIGN_ENDPOINTS": "198.51.100.1 198.51.100.2",
            "AUTO_FAILOVER": "yes",
            "AUTO_FAILBACK": "no",
            "FAILURE_THRESHOLD": "3",
            "RECOVERY_THRESHOLD": "5",
            "FAILOVER_COOLDOWN": "300",
            "CHECK_INTERVAL": "15",
            "HANDSHAKE_STALE_SEC": "100",
            "APP_PORT": "9094",
            "CARRIERS": "wg9094:10.77.94.2:42094 wg9095:10.77.95.2:42095 wg9096:10.77.96.2:42096",
            "UDP2RAW_CONF_DIR": self.udp2raw_dir,
        }
        self.state = {
            "active_endpoint": "198.51.100.1",
            "manual_override": False,
            "cooldown_until": 0,
            "endpoints": {
                "198.51.100.1": {"status": "HEALTHY", "consecutive_failures": 0, "consecutive_successes": 10},
                "198.51.100.2": {"status": "UNKNOWN", "consecutive_failures": 0, "consecutive_successes": 0}
            }
        }
        self.fsm = engine.FailoverStateMachine(self.config, self.state)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_1_primary_healthy(self):
        """When all carriers are healthy, classification is HEALTHY and no failover occurs."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": True, "handshake_age": 10, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": True, "handshake_age": 12, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": True, "handshake_age": 15, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=True)

        res = self.fsm.run_step()
        self.assertEqual(res["classification"], "HEALTHY")
        self.assertFalse(res["needs_failover"])
        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.1")
        self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"], 0)

    def test_2_primary_transient_loss(self):
        """Transient loss (1 or 2 checks) sets SUSPECT state but does NOT trigger failover."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": False, "handshake_age": 130, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 130, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": False, "handshake_age": 130, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=False)

        # Check 1
        res1 = self.fsm.run_step()
        self.assertFalse(res1["needs_failover"])
        self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["status"], "SUSPECT")
        self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"], 1)
        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.1")

        # Check 2
        res2 = self.fsm.run_step()
        self.assertFalse(res2["needs_failover"])
        self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"], 2)
        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.1")

    def test_3_primary_sustained_failure_triggers_failover(self):
        """When consecutive failures reach FAILURE_THRESHOLD (3), failover executes to secondary."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": False, "handshake_age": 150, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 150, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": False, "handshake_age": 150, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=False)
        self.fsm.checker.probe_foreign_carrier_icmp = MagicMock(side_effect=lambda ip: ip == "198.51.100.2")

        # Pre-set 2 failures
        self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"] = 2

        with patch("subprocess.run") as mock_subproc, patch("subprocess.check_output"), patch("time.sleep"):
            mock_subproc.return_value = MagicMock(returncode=0, stdout="peer 1234567890\n")
            res3 = self.fsm.run_step()

        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.2")
        self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["status"], "FAILED")
        self.assertTrue(self.fsm.state["cooldown_until"] > time.time())

        # Verify conf files were updated on disk
        with open(os.path.join(self.udp2raw_dir, "wg9094.conf")) as f:
            self.assertIn("198.51.100.2:42094", f.read())

    def test_4_failover_aborts_if_candidate_unreachable(self):
        """If primary fails but secondary is also unreachable, system marks NO_HEALTHY_ENDPOINT."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": False, "handshake_age": 150, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 150, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": False, "handshake_age": 150, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=False)
        # Both endpoints fail ICMP
        self.fsm.checker.probe_foreign_carrier_icmp = MagicMock(return_value=False)
        self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"] = 2

        self.fsm.run_step()
        self.assertEqual(self.fsm.state["overall_status"], "NO_HEALTHY_ENDPOINT")
        # Active endpoint remains unchanged rather than blindly flapping
        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.1")

    def test_5_cooldown_prevents_rapid_flapping(self):
        """Active cooldown prevents another failover even if checks fail."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": False, "handshake_age": 150, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 150, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": False, "handshake_age": 150, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=False)
        self.fsm.checker.probe_foreign_carrier_icmp = MagicMock(return_value=True)

        self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"] = 5
        self.fsm.state["cooldown_until"] = time.time() + 200

        with patch.object(self.fsm, "execute_failover") as mock_exec:
            self.fsm.run_step()
            mock_exec.assert_not_called()

    def test_6_manual_override_respected(self):
        """When manual_override is true, automatic failover does not occur."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": False, "handshake_age": 150, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 150, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": False, "handshake_age": 150, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=False)
        self.fsm.checker.probe_foreign_carrier_icmp = MagicMock(return_value=True)

        self.fsm.state["endpoints"]["198.51.100.1"]["consecutive_failures"] = 5
        self.fsm.state["manual_override"] = True

        with patch.object(self.fsm, "execute_failover") as mock_exec:
            self.fsm.run_step()
            mock_exec.assert_not_called()

    def test_7_partial_carrier_failure_heals_locally(self):
        """Single degraded carrier is restarted locally without switching remote endpoint."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": True, "handshake_age": 10, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": False, "handshake_age": 150, "gateway": "10.77.95.2"}, # degraded
            "wg9096": {"healthy": True, "handshake_age": 12, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(side_effect=lambda dev, gw: dev != "wg9095")

        self.fsm.carrier_failures = {"wg9094": 0, "wg9095": 2, "wg9096": 0}
        with patch("subprocess.run") as mock_subproc, patch("time.sleep"):
            mock_subproc.return_value = MagicMock(returncode=0)
            res = self.fsm.run_step()

        self.assertEqual(res["classification"], "PARTIAL_CARRIER_DEGRADATION")
        self.assertEqual(self.fsm.state["active_endpoint"], "198.51.100.1")
        # Assert restart was called for wg9095
        mock_subproc.assert_any_call(["systemctl", "restart", "udp2raw-wg9095.service"], capture_output=True)
        mock_subproc.assert_any_call(["systemctl", "restart", "wg-quick@wg9095.service"], capture_output=True)

    def test_8_failback_hysteresis(self):
        """If AUTO_FAILBACK is yes, primary must reach RECOVERY_THRESHOLD (5) before switching back."""
        self.fsm.config["AUTO_FAILBACK"] = "yes"
        self.fsm.state["active_endpoint"] = "198.51.100.2" # on secondary
        self.fsm.state["endpoints"]["198.51.100.2"] = {"status": "HEALTHY", "consecutive_failures": 0, "consecutive_successes": 10}
        self.fsm.state["endpoints"]["198.51.100.1"] = {"status": "FAILED", "consecutive_failures": 3, "consecutive_successes": 0}

        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=[])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": True, "handshake_age": 10, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": True, "handshake_age": 10, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": True, "handshake_age": 10, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=True)
        # Primary begins responding
        self.fsm.checker.probe_foreign_carrier_icmp = MagicMock(return_value=True)

        with patch.object(self.fsm, "execute_failover") as mock_exec:
            # 1 to 4 successes: RECOVERING, no switch
            for i in range(1, 5):
                self.fsm.run_step()
                self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["status"], "RECOVERING")
                mock_exec.assert_not_called()

            # 5th success: STABLE, triggers failback
            self.fsm.run_step()
            self.assertEqual(self.fsm.state["endpoints"]["198.51.100.1"]["status"], "STABLE")
            mock_exec.assert_called_once_with("198.51.100.1", reason="Automatic failback to recovered primary endpoint")

    def test_9_firewall_conflict_detected(self):
        """Firewall conflicts are flagged without breaking the healthy classification."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=[])
        self.fsm.checker.check_firewall_conflicts = MagicMock(return_value=["Rogue table cbtun dnat to 10.21.2.2"])
        self.fsm.checker.get_carrier_passive_signals = MagicMock(return_value={
            "wg9094": {"healthy": True, "handshake_age": 10, "gateway": "10.77.94.2"},
            "wg9095": {"healthy": True, "handshake_age": 10, "gateway": "10.77.95.2"},
            "wg9096": {"healthy": True, "handshake_age": 10, "gateway": "10.77.96.2"}
        })
        self.fsm.checker.check_in_tunnel_reachability = MagicMock(return_value=True)

        res = self.fsm.run_step()
        self.assertTrue(len(res["fw_conflicts"]) > 0)

    def test_10_local_service_failure_classified(self):
        """Local service crash is classified as LOCAL_SERVICE_FAILURE, avoiding endpoint failover."""
        self.fsm.checker.check_local_services = MagicMock(return_value=["udp2raw-wg9094.service is not active"])
        res = self.fsm.run_step()
        self.assertEqual(res["classification"], "LOCAL_SERVICE_FAILURE")
        self.assertFalse(res["needs_failover"])

    def test_11_routing_failure_classified(self):
        """Routing issue is classified as ROUTING_FAILURE, avoiding endpoint failover."""
        self.fsm.checker.check_local_services = MagicMock(return_value=[])
        self.fsm.checker.check_routing_and_forwarding = MagicMock(return_value=["No default route"])
        res = self.fsm.run_step()
        self.assertEqual(res["classification"], "ROUTING_FAILURE")
        self.assertFalse(res["needs_failover"])

    def test_12_state_persistence(self):
        """State written to disk is accurately reloaded."""
        engine.save_state(self.state, self.state_path)
        loaded = engine.load_state(self.state_path)
        self.assertEqual(loaded["active_endpoint"], "198.51.100.1")
        self.assertFalse(loaded["manual_override"])

if __name__ == "__main__":
    unittest.main()
