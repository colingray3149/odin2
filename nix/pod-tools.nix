# Every entry supplies bin/ to the confined workload image. pod-exec never
# invokes a shell: executables and argv slots are registry declarations.
pkgs:
let
  python = pkgs.python3.withPackages (ps: [
    ps.requests
    ps.pillow
  ]);
  # Tools without a native export flag retain their complete stdout, not
  # merely the authority's bounded tail. Each invocation gets a fresh file.
  captured =
    package: name: suffix:
    pkgs.writeShellScriptBin name ''
      set -o pipefail
      output=$(${pkgs.coreutils}/bin/mktemp "/export/${name}-XXXXXXXX.${suffix}")
      ${pkgs.lib.getExe package} "$@" | ${pkgs.coreutils}/bin/tee "$output"
    '';
  # Page review stays in the pod: poppler rasterizes, the host shows the PNG.
  # Typst compiles only through docs.render on the authority.
  reportEnv =
    name: script:
    pkgs.writeShellScriptBin name ''
      export ODIN_PDFTOPPM=${pkgs.poppler-utils}/bin/pdftoppm
      exec ${python}/bin/python3 ${script} "$@"
    '';
  reportSource = reportEnv "odin-source" ./report-source.py;
  reportPages = reportEnv "odin-pages" ./report-pages.py;
  reportView = reportEnv "odin-view" ./report-view.py;
  vpnTun = import ./vpn-tun.nix { inherit pkgs; };
in
[
  pkgs.poppler-utils
  reportSource
  reportPages
  reportView
  # Agent-written scripts with inline dependencies: `uv run analysis.py` (settings in the image Env).
  pkgs.uv
  vpnTun
]
