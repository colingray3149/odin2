#!/usr/bin/env bash
# Drive `odin view` the way the owner sees it: Konsole running Zellij running the view, inside a headless sway
# (or the real desktop with DRIVE_DISPLAY=$WAYLAND_DISPLAY), with keys, wheel and screenshots from outside.
#   drive.sh start [WxH]    start sway + Konsole + Zellij session "viewdrive" running the view from this tree
#   drive.sh keys TEXT...   type text (write-chars) into the view's pane
#   drive.sh key NAME...    send keys: Enter Esc Tab BTab PgUp PgDn Up Down End Home C-c C-d C-r C-Up C-Down
#   drive.sh wheel up|down [N [DX DY]]  N wheel clicks DX,DY left of and above the display's bottom-right corner (a
#                           virtual pointer, aimed from that corner since niri's top-left is a hot corner; needs a
#                           display with a real pointer, so DRIVE_DISPLAY: a headless sway's seat has none)
#   drive.sh shot FILE.png  screenshot the display
#   drive.sh text           the pane as plain text; `text -a` keeps colours
#   drive.sh stop
# Env: ODIN_VIEW_BRIDGE_BIN, the odin binary (default: odin on PATH); DRIVE_ENTRY, the view (default: this tree);
# DRIVE_DISPLAY, a live Wayland display to use instead of a headless sway.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
run=${XDG_RUNTIME_DIR:-/tmp}/viewdrive
session=viewdrive
poll=0.2 key_gap=0.15 # seconds between checks for a starting display or session, and between sent keys
tools=(nixpkgs#sway nixpkgs#grim nixpkgs#wlrctl)
mkdir -p "$run"

in_tools() { nix shell "${tools[@]}" -c "$@"; }
display() { cat "$run/display"; }
zj() { zellij -s "$session" action "$@"; }

case "${1:-}" in
start)
	unset ZELLIJ ZELLIJ_PANE_ID ZELLIJ_SESSION_NAME # started from inside Zellij, the new client would refuse to nest
	size=${2:-1600x1000}
	bun=${ODIN_VIEW_BUN:-$(nix eval --raw nixpkgs#bun)/bin/bun}
	odin=${ODIN_VIEW_BRIDGE_BIN:-$(command -v odin)}
	cat >"$run/layout.kdl" <<-EOF
		layout {
		  default_tab_template {
		    pane size=1 borderless=true { plugin location="zellij:tab-bar"; }
		    children
		    pane size=2 borderless=true { plugin location="zellij:status-bar"; }
		  }
		  tab name="view" {
		    pane command="env" {
		      args "ODIN_VIEW_BUN=$bun" "ODIN_VIEW_ENTRY=${DRIVE_ENTRY:-$here/main.ts}" "$odin" "view"
		    }
		  }
		}
	EOF
	if [ -n "${DRIVE_DISPLAY:-}" ]; then
		echo "$DRIVE_DISPLAY" >"$run/display"
	else
		cat >"$run/sway.conf" <<-EOF
			output HEADLESS-1 resolution $size bg #1d1620 solid_color
			default_border none
		EOF
		sockets() { for s in "$XDG_RUNTIME_DIR"/wayland-[0-9]*; do [ -e "$s" ] && [ "${s%.lock}" = "$s" ] && echo "${s##*/}"; done; }
		before=$(sockets)
		WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WAYLAND_DISPLAY="" \
			setsid nix shell "${tools[@]}" -c sway -c "$run/sway.conf" >"$run/sway.log" 2>&1 &
		name=
		for _ in $(seq 50); do
			name=$(sockets | grep -vxF "$before" | head -1 || true)
			[ -n "$name" ] && break
			sleep "$poll"
		done
		[ -n "$name" ] || { echo "drive: sway did not start: $(tail -3 "$run/sway.log")" >&2; exit 1; }
		echo "$name" >"$run/display"
	fi
	# Wayland only (with DISPLAY set it could open on the desktop's X server); zellij's short flags, since Konsole takes --session as Qt session restore.
	env -u DISPLAY QT_QPA_PLATFORM=wayland WAYLAND_DISPLAY="$(display)" konsole --hide-menubar -e zellij -s "$session" -n "$run/layout.kdl" \
		>"$run/konsole.log" 2>&1 &
	for _ in $(seq 50); do zellij list-sessions -n 2>/dev/null | grep -q "^$session " && break; sleep "$poll"; done
	echo "drive: view running in Zellij session $session on $(display)"
	;;
keys)
	shift
	zj write-chars "$*"
	;;
key)
	shift
	for k in "$@"; do
		case $k in
		Enter) b='13' ;; Esc) b='27' ;; Tab) b='9' ;; BTab) b='27 91 90' ;;
		PgUp) b='27 91 53 126' ;; PgDn) b='27 91 54 126' ;; Up) b='27 91 65' ;; Down) b='27 91 66' ;;
		End) b='27 91 70' ;; Home) b='27 91 72' ;; C-Up) b='27 91 49 59 53 65' ;; C-Down) b='27 91 49 59 53 66' ;;
		C-?) b=$(($(printf '%d' "'${k#C-}") & 31)) ;;
		*) echo "drive: unknown key $k" >&2; exit 2 ;;
		esac
		# shellcheck disable=SC2086
		zj write $b
		sleep "$key_gap"
	done
	;;
wheel)
	dir=${2:-up}
	n=${3:-3}
	step=$([ "$dir" = up ] && echo -15 || echo 15)
	WAYLAND_DISPLAY=$(display) in_tools sh -c "wlrctl pointer move 10000 10000; wlrctl pointer move -${4:-600} -${5:-400}; sleep 0.3
		for i in \$(seq $n); do wlrctl pointer scroll $step 0; sleep 0.08; done"
	;;
shot)
	WAYLAND_DISPLAY=$(display) in_tools grim "${2:?drive: shot FILE.png}"
	;;
text)
	if [ "${2:-}" = -a ]; then zj dump-screen --ansi; else zj dump-screen; fi
	;;
stop)
	zellij kill-session "$session" 2>/dev/null || true
	zellij delete-session "$session" 2>/dev/null || true
	pkill -f "sway -c $run/sway.conf" 2>/dev/null || true
	;;
*)
	sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
