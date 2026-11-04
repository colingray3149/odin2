"""vpn-tun.py programs iptables and routes as root in a pod's sidecar: its rules and guards on a fake `run`."""

import argparse
import importlib.util
import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("vpn_tun", Path(__file__).with_name("vpn-tun.py"))
VPN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN)


class RuleChecks(unittest.TestCase):
    def rules(self, **kwargs):
        with patch.object(VPN, "rule") as rule:
            VPN.public_rules("CHAIN", **kwargs)
        return [call.args for call in rule.call_args_list]

    def test_private_ranges_are_refused_before_the_public_ports_open_and_everything_else_ends_refused(self):
        rules = self.rules(addresses=["93.184.216.34"])
        refused = [argv[3] for argv in rules if argv[-1] == "REJECT" and "-d" in argv]
        self.assertEqual(refused, list(VPN.PRIVATE))
        first_accept = next(i for i, argv in enumerate(rules) if argv[-1] == "ACCEPT")
        self.assertGreater(first_accept, len(VPN.PRIVATE) - 1)
        accepts = [argv for argv in rules if argv[-1] == "ACCEPT"]
        self.assertEqual(len(accepts), 2)
        self.assertTrue(all(argv[argv.index("-d") + 1] == "93.184.216.34" for argv in accepts))
        self.assertIn("43,80,443", accepts[0])
        self.assertEqual(rules[-1], ("-A", "CHAIN", "-j", "REJECT"))

    def test_an_open_policy_accepts_the_public_ports_for_any_destination(self):
        accepts = [argv for argv in self.rules() if argv[-1] == "ACCEPT"]
        self.assertEqual(len(accepts), 2)
        self.assertTrue(all("-d" not in argv for argv in accepts))


class RouteChecks(unittest.TestCase):
    def route(self, answer):
        calls = []

        def fake(*argv, check=True):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps([answer]))

        with patch.object(VPN, "run", fake):
            VPN.pinned_route("203.0.113.9")
        return calls[-1]

    def test_an_address_stays_on_the_route_it_has_now_through_its_gateway_when_it_has_one(self):
        self.assertEqual(self.route({"dev": "eth0", "gateway": "10.42.0.1"})[3:], ("203.0.113.9/32", "via", "10.42.0.1", "dev", "eth0"))
        self.assertEqual(self.route({"dev": "eth0"})[3:], ("203.0.113.9/32", "dev", "eth0"))


class ClientGuards(unittest.TestCase):
    args = argparse.Namespace(endpoint="198.51.100.7", port=51820, gateway=[], gateway_port=443, allow=[], open=True, closed=False)

    def refuse(self, pod_ip):
        with patch.dict(os.environ, {"POD_IP": pod_ip}), patch.object(VPN, "run"), patch.object(VPN.os, "unlink", side_effect=FileNotFoundError):
            with self.assertRaises(ValueError) as caught:
                VPN.client(self.args)
        return str(caught.exception)

    def test_a_pod_outside_the_fleet_range_or_whose_tunnel_address_is_the_dns_endpoint_gets_no_rules(self):
        self.assertIn("no fleet pod address", self.refuse("192.168.1.5"))
        self.assertIn("collides with its DNS endpoint", self.refuse("10.42.0.1"))


if __name__ == "__main__":
    unittest.main()
