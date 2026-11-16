#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import signal
import subprocess
import sys
import time

IP = "@ip@"
IPTABLES = "@iptables@"
IP6TABLES = "@ip6tables@"
GOST = "@gost@"
DNS = "198.18.0.1"
# The egress pool's SOCKS listeners on the DNS address, one port per exit (dotfiles pool).
POOL_PORTS = "1081:1088"
TUN = "odin-vpn"
TRANSPORT_MARK = 0x4F440000
# The public-only workload policy's excluded IPv4 ranges.
PRIVATE = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def run(*argv, check=True):
    return subprocess.run(argv, check=check, stdout=subprocess.PIPE, text=True)


def rule(*argv):
    run(IPTABLES, "-w", *argv)


def ensure(chain_name, *arguments, table="filter"):
    prefix = [IPTABLES, "-w", "-t", table]
    if run(*prefix, "-C", chain_name, *arguments, check=False).returncode:
        run(*prefix, "-I", chain_name, "1", *arguments)


def chain(name):
    run(IPTABLES, "-w", "-N", name, check=False)
    rule("-F", name)


def public_rules(name, addresses=None):
    for network in PRIVATE:
        rule("-A", name, "-d", network, "-j", "REJECT")
    for destination in [None] if addresses is None else addresses:
        target = [] if destination is None else ["-d", destination]
        rule(
            "-A",
            name,
            *target,
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "43,80,443",
            "-j",
            "ACCEPT",
        )
        rule("-A", name, *target, "-p", "udp", "--dport", "443", "-j", "ACCEPT")
    rule("-A", name, "-j", "REJECT")


def pinned_route(address):
    route = json.loads(run(IP, "-j", "route", "get", address).stdout)[0]
    argv = [IP, "route", "replace", f"{address}/32"]
    if route.get("gateway"):
        argv.extend(["via", route["gateway"]])
    argv.extend(["dev", route["dev"]])
    run(*argv)


def client(args):
    os.environ["XTABLES_LOCKFILE"] = "/run/odin-vpn/xtables.lock"
    try:
        os.unlink("/run/odin-vpn/ready")
    except FileNotFoundError:
        pass
    endpoint = str(ipaddress.IPv4Address(args.endpoint))
    pod = ipaddress.IPv4Address(os.environ["POD_IP"])
    if pod not in ipaddress.IPv4Network("10.42.0.0/16"):
        raise ValueError("VPN-required workload has no fleet pod address")
    inner = ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.18.0.0")) + (int(pod) & 0xFFFF))
    if str(inner) == DNS:
        raise ValueError("VPN-required workload address collides with its DNS endpoint")
    gateways = []
    for address in args.gateway:
        gateways.append((str(ipaddress.IPv4Address(address)), str(args.gateway_port)))
    allowed = [str(ipaddress.IPv4Address(address)) for address in args.allow]
    # Drop first, including on sidecar restart; rebuilding rules never opens the pod.
    rule("-P", "OUTPUT", "DROP")
    run(IP6TABLES, "-w", "-P", "OUTPUT", "DROP")
    chain("ODIN_VPN")
    chain("ODIN_PUBLIC")
    rule("-A", "ODIN_VPN", "-o", "lo", "-j", "ACCEPT")
    rule(
        "-A",
        "ODIN_VPN",
        "-d",
        endpoint,
        "-p",
        "udp",
        "--dport",
        str(args.port),
        "-m",
        "mark",
        "--mark",
        str(TRANSPORT_MARK),
        "-j",
        "ACCEPT",
    )
    for address, port in gateways:
        rule("-A", "ODIN_VPN", "-d", address, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
    for protocol in ("tcp", "udp"):
        rule(
            "-A", "ODIN_VPN", "-o", TUN, "-d", DNS, "-p", protocol, "--dport", "53", "-j", "ACCEPT"
        )
    rule("-A", "ODIN_VPN", "-o", TUN, "-d", DNS, "-p", "tcp", "--dport", POOL_PORTS, "-j", "ACCEPT")
    public_rules("ODIN_PUBLIC", None if args.open else allowed)
    rule("-A", "ODIN_VPN", "-o", TUN, "-j", "ODIN_PUBLIC")
    rule("-A", "ODIN_VPN", "-j", "REJECT")
    if run(IPTABLES, "-w", "-C", "OUTPUT", "-j", "ODIN_VPN", check=False).returncode:
        rule("-I", "OUTPUT", "1", "-j", "ODIN_VPN")
    for address in {endpoint, *(address for address, _ in gateways)}:
        pinned_route(address)
    # An unavailable TUN leaves no internet route, not the original CNI default.
    run(IP, "route", "flush", "default")
    run(IP, "-6", "route", "flush", "default")
    process = subprocess.Popen(
        [
            GOST,
            "-L",
            f"tun://:0/{endpoint}:{args.port}?net={inner}/32&name={TUN}&mtu=1280&keepalive=true&so_mark={TRANSPORT_MARK}",
        ]
    )

    def stop(_signal, _frame):
        process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while run(IP, "link", "show", TUN, check=False).returncode:
            if process.poll() is not None:
                raise RuntimeError(
                    "VPN-required packet transport exited before its interface was ready"
                )
            time.sleep(0.05)
        run(IP, "route", "replace", "default", "dev", TUN)
        with open("/run/odin-vpn/ready", "w", encoding="ascii") as ready:
            ready.write("ready\n")
        result = process.wait()
        raise RuntimeError(
            f"VPN-required packet transport exited ({result}); direct egress remains blocked"
        )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


def server_filter(args):
    # INPUT and FORWARD are already fail-closed in the existing VPN namespace.
    chain("ODIN_RESEARCH")
    public_rules("ODIN_RESEARCH")
    for interface in ("odin-pods", "odin-research"):
        for protocol in ("tcp", "udp"):
            ensure(
                "INPUT", "-i", interface, "-d", DNS, "-p", protocol, "--dport", "53", "-j", "ACCEPT"
            )
        ensure("INPUT", "-i", interface, "-d", DNS, "-p", "tcp", "--dport", POOL_PORTS, "-j", "ACCEPT")
        ensure(
            "FORWARD",
            "-i",
            args.vpn_interface,
            "-o",
            interface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )
        # Only the provider interface is a forwarding destination, even after tunnel loss.
        ensure("FORWARD", "-i", interface, "-o", args.vpn_interface, "-j", "ODIN_RESEARCH")
    ensure(
        "POSTROUTING",
        "-o",
        args.vpn_interface,
        "-s",
        "198.18.0.0/15",
        "-j",
        "MASQUERADE",
        table="nat",
    )
    ensure(
        "INPUT",
        "-i",
        "veth-vpn",
        "-s",
        "192.168.15.5",
        "-d",
        "192.168.15.1",
        "-p",
        "udp",
        "--dport",
        str(args.port),
        "-j",
        "ACCEPT",
    )
    run(IP, "link", "set", "odin-research", "up")


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    setup = actions.add_parser("client")
    setup.add_argument("--endpoint", required=True)
    setup.add_argument("--port", type=int, required=True)
    setup.add_argument("--gateway", action="append", default=[])
    setup.add_argument("--gateway-port", type=int, default=443)
    scope = setup.add_mutually_exclusive_group(required=True)
    scope.add_argument("--open", action="store_true")
    scope.add_argument("--closed", action="store_true")
    scope.add_argument("--allow", action="append", default=[])
    server = actions.add_parser("server-filter")
    server.add_argument("--vpn-interface", required=True)
    server.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.action == "client":
            client(args)
        else:
            server_filter(args)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"VPN-required transport unavailable: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
