# odin-look: code.look's fixed program, run by the effector inside the capsule bubble.
{ pkgs }:
pkgs.writeShellApplication {
  name = "odin-look";
  runtimeInputs = [
    pkgs.nodejs_22
    pkgs.bash
    pkgs.coreutils
    pkgs.python3
  ];
  text = ''
    export HOME="''${HOME:-/tmp}"
    export ODIN_LOOK_PLAYWRIGHT=${pkgs.playwright-driver}
    export ODIN_LOOK_CHROMIUM=${pkgs.chromium}/bin/chromium
    # The bubble has no /etc/fonts; pages render with these instead of empty boxes.
    export FONTCONFIG_FILE=${pkgs.makeFontsConf {
      fontDirectories = with pkgs; [
        dejavu_fonts
        noto-fonts
        noto-fonts-cjk-sans
        noto-fonts-cjk-serif
        noto-fonts-color-emoji
      ];
    }}
    exec node ${./look/look.mjs} "$@"
  '';
}
