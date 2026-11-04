{ pkgs }:
let
  source = pkgs.replaceVars ./vpn-tun.py {
    ip = "${pkgs.iproute2}/bin/ip";
    iptables = "${pkgs.iptables}/bin/iptables";
    ip6tables = "${pkgs.iptables}/bin/ip6tables";
    gost = "${pkgs.gost}/bin/gost";
  };
in
pkgs.writeShellScriptBin "odin-vpn-tun" ''
  exec ${pkgs.python3}/bin/python3 ${source} client "$@"
''
